namespace Tether.Shared.DTO
{
    public class PhonePresence
    {
        public string DeviceName { get; set; } = "";
        public string BluetoothAddress { get; set; } = "";
        public bool IsConnected { get; set; }
        public bool IsUnlocked { get; set; }
        public int Rssi { get; set; }
    }
}