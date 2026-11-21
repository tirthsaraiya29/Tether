using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.Tests;

public class EventBusConcurrencyTests
{
    [Fact]
    public async Task EventBus_ConcurrentPublishSubscribeUnsubscribe_ThreadSafe()
    {
        var logger = new TestLogger();
        var bus = new InMemoryEventBus(logger);

        int eventsReceived = 0;
        var handlers = new List<Action<TetherEvent>>();

        for (int i = 0; i < 50; i++)
        {
            Action<TetherEvent> handler = e => Interlocked.Increment(ref eventsReceived);
            handlers.Add(handler);
            bus.Subscribe(handler);
        }

        var tasks = new List<Task>();

        // Concurrent publish
        for (int i = 0; i < 20; i++)
        {
            tasks.Add(Task.Run(() =>
            {
                bus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "dev-test" });
            }));
        }

        // Concurrent unsubscribe
        for (int i = 0; i < 25; i++)
        {
            var h = handlers[i];
            tasks.Add(Task.Run(() =>
            {
                bus.Unsubscribe(h);
            }));
        }

        // Concurrent subscribe
        for (int i = 0; i < 25; i++)
        {
            tasks.Add(Task.Run(() =>
            {
                bus.Subscribe(e => { });
            }));
        }

        await Task.WhenAll(tasks);

        // Verify no deadlock, no exceptions, and events were processed
        Assert.True(eventsReceived > 0);
    }
}
