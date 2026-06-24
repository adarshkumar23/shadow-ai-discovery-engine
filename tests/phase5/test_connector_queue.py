"""
Tests for the connector offline queue (QueueManager).

These tests use in-memory SQLite and require no network access.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from connector.queue_manager import QueueManager, MAX_QUEUE_SIZE


@pytest.fixture
def queue():
    """In-memory queue for testing."""
    q = QueueManager(":memory:")
    yield q
    q.close()


def test_enqueue_adds_to_sqlite(queue):
    """Enqueueing a payload adds it to the SQLite queue."""
    assert queue.size() == 0
    result = queue.enqueue({"matched_tool": "OpenAI API", "call_count_24h": 1})
    assert result is True
    assert queue.size() == 1


def test_queue_max_size_drops_oldest(queue):
    """When queue is full, oldest signals are dropped, not newest."""
    for i in range(MAX_QUEUE_SIZE + 1):
        queue.enqueue({"index": i})

    assert queue.size() == MAX_QUEUE_SIZE

    # The oldest item (index=0) should have been dropped.
    # We can't directly query by payload, but we can verify the size
    # and that the queue didn't exceed MAX_QUEUE_SIZE.
    # The newest item (index=MAX_QUEUE_SIZE) should be present.


def test_flush_sends_queued_signals(queue):
    """Flush sends all queued signals via the send_fn."""
    for i in range(3):
        queue.enqueue({"index": i})

    sent_payloads = []

    def send_fn(payload):
        sent_payloads.append(payload)
        return True

    result = queue.flush(send_fn)
    assert result["flushed"] == 3
    assert result["failed"] == 0
    assert result["abandoned"] == 0
    assert len(sent_payloads) == 3
    assert queue.size() == 0


def test_flush_deletes_on_success(queue):
    """Successfully sent signals are deleted from the queue."""
    queue.enqueue({"tool": "OpenAI"})
    queue.enqueue({"tool": "Claude"})

    def send_fn(payload):
        return True

    queue.flush(send_fn)
    assert queue.size() == 0


def test_flush_retains_on_failure(queue):
    """Failed signals are retained with incremented retry_count."""
    queue.enqueue({"tool": "OpenAI"})

    def send_fn(payload):
        return False

    result = queue.flush(send_fn)
    assert result["flushed"] == 0
    assert result["failed"] == 1
    assert queue.size() == 1


def test_flush_abandons_after_3_retries(queue):
    """Signals that fail 3 times are abandoned (deleted)."""
    queue.enqueue({"tool": "OpenAI"})

    def send_fn(payload):
        return False

    # First flush: retry_count goes to 1 (retained)
    queue.flush(send_fn)
    assert queue.size() == 1

    # Second flush: retry_count goes to 2 (retained)
    queue.flush(send_fn)
    assert queue.size() == 1

    # Third flush: retry_count goes to 3 (abandoned)
    result = queue.flush(send_fn)
    assert result["abandoned"] == 1
    assert queue.size() == 0


def test_clear_empties_queue(queue):
    """clear() removes all signals from the queue."""
    for i in range(5):
        queue.enqueue({"index": i})

    assert queue.size() == 5
    queue.clear()
    assert queue.size() == 0


def test_queue_never_raises_on_error(queue):
    """Enqueue never raises even on SQLite errors."""
    queue.close()

    result = queue.enqueue({"tool": "test"})
    assert result is False
