# ============================================================
# services/lease_expiry_scheduler.py
# ResidEase – Boarding House Management System
#
# Runs background jobs to:
# 1. Expire leases whose end_date has passed
# 2. Flag leases expiring within 30 days (is_expiring_soon)
# 3. Auto-renew leases with auto_renew = True
#
# Equivalent to @Scheduled in Spring Boot.
# Uses APScheduler — install with:
#   pip install apscheduler
# ============================================================

import logging
from datetime import date, datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from repository import lease_repository
from services import lease_service
from models.lease import LeaseStatus, PaymentFrequency

logger = logging.getLogger(__name__)


# ================================================================
# SCHEDULER INSTANCE
# Single shared scheduler — started in main.py lifespan()
# ================================================================

scheduler = AsyncIOScheduler(timezone="Asia/Manila")


# ================================================================
# JOB 1 — EXPIRE OVERDUE LEASES
# Runs daily at 00:05 AM Manila time
# ================================================================

async def expire_overdue_leases() -> None:
    """
    Finds all ACTIVE leases whose end_date has passed
    and marks them as EXPIRED.

    Side effects per lease:
    - Sets lease status to EXPIRED
    - Vacates the room (room → VACANT)
    - Unassigns the tenant (tenant → MOVED_OUT)

    Logs a summary of how many leases were expired.
    """
    logger.info("[Scheduler] expire_overdue_leases — started")

    today = date.today()
    expired_count = 0
    error_count   = 0

    try:
        overdue_leases = await lease_repository.get_overdue_leases(
            as_of_date=today
        )

        if not overdue_leases:
            logger.info("[Scheduler] expire_overdue_leases — no overdue leases found")
            return

        logger.info(
            f"[Scheduler] expire_overdue_leases — "
            f"found {len(overdue_leases)} overdue lease(s)"
        )

        for lease in overdue_leases:
            try:
                await lease_service.expire_lease(
                    lease_id=lease.id,
                    updated_by="system_scheduler",
                )
                expired_count += 1
                logger.info(
                    f"[Scheduler] Expired lease {lease.id} | "
                    f"tenant={lease.tenant_id} | "
                    f"room={lease.room_id} | "
                    f"end_date={lease.end_date}"
                )
            except Exception as e:
                error_count += 1
                logger.error(
                    f"[Scheduler] Failed to expire lease {lease.id}: {e}"
                )

    except Exception as e:
        logger.error(f"[Scheduler] expire_overdue_leases — fatal error: {e}")

    finally:
        logger.info(
            f"[Scheduler] expire_overdue_leases — done | "
            f"expired={expired_count} | errors={error_count}"
        )


# ================================================================
# JOB 2 — FLAG EXPIRING SOON LEASES
# Runs daily at 00:10 AM Manila time
# ================================================================

async def flag_expiring_soon_leases(days_ahead: int = 30) -> None:
    """
    Finds all ACTIVE leases expiring within `days_ahead` days
    and sets is_expiring_soon = True on each.

    Also resets is_expiring_soon = False on leases that were
    previously flagged but have since been renewed.

    Used by:
    - Dashboard expiring-soon alert card
    - Notification job (Job 4) to send tenant reminders
    """
    logger.info(
        f"[Scheduler] flag_expiring_soon_leases — "
        f"started (days_ahead={days_ahead})"
    )

    flagged_count  = 0
    unflagged_count = 0
    error_count    = 0

    try:
        # ── Flag leases expiring within days_ahead ────────────
        expiring_leases = await lease_repository.get_expiring_leases(
            days_ahead=days_ahead,
            skip=0,
            limit=1000,
        )

        for lease in expiring_leases:
            if not lease.is_expiring_soon:
                try:
                    await lease_repository.update_lease(
                        lease_id=lease.id,
                        updates={"is_expiring_soon": True},
                        updated_by="system_scheduler",
                    )
                    flagged_count += 1
                    logger.info(
                        f"[Scheduler] Flagged lease {lease.id} as expiring soon | "
                        f"end_date={lease.end_date} | "
                        f"days_remaining={lease.days_remaining}"
                    )
                except Exception as e:
                    error_count += 1
                    logger.error(
                        f"[Scheduler] Failed to flag lease {lease.id}: {e}"
                    )

        # ── Unflag leases that were renewed or extended ───────
        wrongly_flagged = await lease_repository.get_wrongly_flagged_leases(
            days_ahead=days_ahead
        )

        for lease in wrongly_flagged:
            try:
                await lease_repository.update_lease(
                    lease_id=lease.id,
                    updates={"is_expiring_soon": False},
                    updated_by="system_scheduler",
                )
                unflagged_count += 1
                logger.info(
                    f"[Scheduler] Unflagged lease {lease.id} "
                    f"(no longer expiring soon)"
                )
            except Exception as e:
                error_count += 1
                logger.error(
                    f"[Scheduler] Failed to unflag lease {lease.id}: {e}"
                )

    except Exception as e:
        logger.error(
            f"[Scheduler] flag_expiring_soon_leases — fatal error: {e}"
        )

    finally:
        logger.info(
            f"[Scheduler] flag_expiring_soon_leases — done | "
            f"flagged={flagged_count} | "
            f"unflagged={unflagged_count} | "
            f"errors={error_count}"
        )


# ================================================================
# JOB 3 — AUTO-RENEW LEASES
# Runs daily at 00:15 AM Manila time
# ================================================================

async def auto_renew_leases(default_extension_months: int = 12) -> None:
    """
    Finds all ACTIVE leases with auto_renew = True
    that are expiring within the next 3 days and
    automatically renews them for another term.

    Extension period defaults to 12 months.
    Monthly rate stays the same on auto-renewal.


    """
    logger.info("[Scheduler] auto_renew_leases — started")

    renewed_count = 0
    error_count   = 0

    try:
        auto_renew_candidates = await lease_repository.get_auto_renew_candidates(
            days_ahead=3
        )

        if not auto_renew_candidates:
            logger.info(
                "[Scheduler] auto_renew_leases — no candidates found"
            )
            return

        logger.info(
            f"[Scheduler] auto_renew_leases — "
            f"found {len(auto_renew_candidates)} candidate(s)"
        )

        for lease in auto_renew_candidates:
            try:
                from dto.request.lease_request import LeaseRenewRequest

                # Extend end_date by default_extension_months
                current_end = lease.end_date
                new_end = current_end.replace(
                    year=current_end.year + (
                        (current_end.month + default_extension_months - 1) // 12
                    ),
                    month=(
                        (current_end.month + default_extension_months - 1) % 12
                    ) + 1,
                )

                renew_request = LeaseRenewRequest(
                    new_end_date=new_end,
                    new_monthly_rate=None,    # keep existing rate
                    notes=f"Auto-renewed by scheduler for {default_extension_months} months.",
                )

                await lease_service.renew_lease(
                    lease_id=lease.id,
                    request=renew_request,
                    updated_by="system_scheduler",
                )

                renewed_count += 1
                logger.info(
                    f"[Scheduler] Auto-renewed lease {lease.id} | "
                    f"tenant={lease.tenant_id} | "
                    f"old_end={current_end} | "
                    f"new_end={new_end}"
                )

            except Exception as e:
                error_count += 1
                logger.error(
                    f"[Scheduler] Failed to auto-renew lease {lease.id}: {e}"
                )

    except Exception as e:
        logger.error(f"[Scheduler] auto_renew_leases — fatal error: {e}")

    finally:
        logger.info(
            f"[Scheduler] auto_renew_leases — done | "
            f"renewed={renewed_count} | errors={error_count}"
        )


# ================================================================
# JOB 4 — SEND EXPIRY REMINDER NOTIFICATIONS
# Runs daily at 08:00 AM Manila time
# ================================================================

async def send_expiry_reminders() -> None:
    """
    Finds all leases flagged with is_expiring_soon = True
    and sends a reminder notification to the tenant.

    Reminder intervals:
    - 30 days before expiry → first reminder
    - 14 days before expiry → second reminder
    - 7  days before expiry → urgent reminder
    - 3  days before expiry → final reminder

    Notification is sent via NotificationService (stub below).
    Replace with actual implementation when NotificationService
    is built.
    """
    logger.info("[Scheduler] send_expiry_reminders — started")

    sent_count  = 0
    error_count = 0

    reminder_intervals = [30, 14, 7, 3]

    try:
        expiring_leases = await lease_repository.get_expiring_leases(
            days_ahead=30,
            skip=0,
            limit=1000,
        )

        for lease in expiring_leases:
            days_left = lease.days_remaining

            if days_left not in reminder_intervals:
                continue

            try:
                # ── Stub — replace with NotificationService.send() ──
                logger.info(
                    f"[Scheduler] NOTIFY tenant={lease.tenant_id} | "
                    f"lease={lease.id} | "
                    f"days_remaining={days_left} | "
                    f"end_date={lease.end_date} | "
                    f"message='Your lease expires in {days_left} day(s). "
                    f"Please contact management to renew.'"
                )
                sent_count += 1

            except Exception as e:
                error_count += 1
                logger.error(
                    f"[Scheduler] Failed to notify tenant "
                    f"{lease.tenant_id} for lease {lease.id}: {e}"
                )

    except Exception as e:
        logger.error(
            f"[Scheduler] send_expiry_reminders — fatal error: {e}"
        )

    finally:
        logger.info(
            f"[Scheduler] send_expiry_reminders — done | "
            f"sent={sent_count} | errors={error_count}"
        )


# ================================================================
# JOB 5 — HEALTH CHECK LOG
# Runs every hour — confirms scheduler is alive
# ================================================================

async def scheduler_health_check() -> None:
    """
    Logs a heartbeat every hour to confirm the scheduler
    is running. Useful for monitoring and debugging.
    """
    logger.info(
        f"[Scheduler] health_check — alive at "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )


# ================================================================
# REGISTER JOBS
# ================================================================

def register_jobs() -> None:
    """
    Registers all scheduler jobs with their triggers.
    Called once during application startup.

    Cron schedule (Manila time, UTC+8):
    - 00:05  expire_overdue_leases
    - 00:10  flag_expiring_soon_leases
    - 00:15  auto_renew_leases
    - 08:00  send_expiry_reminders
    - every hour  scheduler_health_check
    """
    # Job 1 — Expire overdue leases (daily 00:05)
    scheduler.add_job(
        func=expire_overdue_leases,
        trigger=CronTrigger(hour=0, minute=5, timezone="Asia/Manila"),
        id="expire_overdue_leases",
        name="Expire Overdue Leases",
        replace_existing=True,
        misfire_grace_time=3600,   # retry within 1 hour if missed
    )

    # Job 2 — Flag expiring soon (daily 00:10)
    scheduler.add_job(
        func=flag_expiring_soon_leases,
        trigger=CronTrigger(hour=0, minute=10, timezone="Asia/Manila"),
        id="flag_expiring_soon_leases",
        name="Flag Expiring Soon Leases",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # Job 3 — Auto-renew leases (daily 00:15)
    scheduler.add_job(
        func=auto_renew_leases,
        trigger=CronTrigger(hour=0, minute=15, timezone="Asia/Manila"),
        id="auto_renew_leases",
        name="Auto-Renew Leases",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # Job 4 — Send expiry reminders (daily 08:00)
    scheduler.add_job(
        func=send_expiry_reminders,
        trigger=CronTrigger(hour=8, minute=0, timezone="Asia/Manila"),
        id="send_expiry_reminders",
        name="Send Lease Expiry Reminders",
        replace_existing=True,
        misfire_grace_time=3600,
    )

    # Job 5 — Health check (every hour)
    scheduler.add_job(
        func=scheduler_health_check,
        trigger=IntervalTrigger(hours=1),
        id="scheduler_health_check",
        name="Scheduler Health Check",
        replace_existing=True,
    )

    logger.info("[Scheduler] All jobs registered successfully.")


# ================================================================
# STARTUP / SHUTDOWN
# Called from main.py lifespan()
# ================================================================

def start_scheduler() -> None:
    """
    Registers all jobs and starts the scheduler.
    Called once on application startup.
    """
    register_jobs()
    scheduler.start()
    logger.info("[Scheduler] APScheduler started.")


def stop_scheduler() -> None:
    """
    Gracefully shuts down the scheduler.
    Called on application shutdown.
    """
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("[Scheduler] APScheduler stopped.")