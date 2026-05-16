using Tether.Shared.Events;

namespace Tether.EventBus
{
    public interface IEventBus
    {
        void Publish(TetherEvent evt);
        void Subscribe(Action<TetherEvent> handler);
        void Unsubscribe(Action<TetherEvent> handler);
    }
}