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
        LOCK_WORKSTATION
    }

    public class TetherEvent
    {
        public TetherEventType EventType { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string? Source { get; set; }
        public string? PayloadJson { get; set; }
    }
}