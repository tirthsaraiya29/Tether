namespace Tether.Shared.Events
{
    public enum TetherEventType
    {
        PHONE_CONNECTED,
        PHONE_DISCONNECTED,
        PHONE_UNLOCKED,
        PHONE_LOCKED,
        PANIC_TRIGGERED,
        PANIC_CLEARED,
        RECOVERY_STARTED,
        RECOVERY_COMPLETED,
        RECOVERY_FAILED,
        TRUST_DEGRADED,
        TRUST_RESTORED,
        TRUST_LOST,
        OVERLAY_ENABLED,
        OVERLAY_DISABLED,
        AUTH_SUCCESS,
        AUTH_FAILURE,
        LOCK_WORKSTATION,
        PROVISION_PHONE,
        PAIRING_REQUESTED,
        PAIRING_DECISION,
        FORGET_PHONE,
        TELEMETRY_SYNC_REQUESTED,
        FILE_TRANSFER_REQUESTED,
        FILE_TRANSFER_PROGRESS,
        FILE_TRANSFER_COMPLETED,
        FILE_TRANSFER_FAILED,
        FILE_TRANSFER_CANCELLED,
        FILE_TRANSFER_CANCEL_REQUESTED,
        FILE_TRANSFER_ENQUEUE_REQUESTED
    }

    public class TetherEvent
    {
        public TetherEventType EventType { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string? Source { get; set; }
        public string? PayloadJson { get; set; }
    }
}