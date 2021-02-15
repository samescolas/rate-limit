<?php

if (!session_id()) {
  session_start();
}

declare(strict_types=1);

namespace RateLimit;

use RateLimit\Exception\LimitExceeded;
use function floor;
use function time;

final class SessionRateLimiter implements RateLimiter, SilentRateLimiter
{
    if (!isset($_SESSION["ers-rate-limiter"])) {
      $_SESSION["ers-rate-limiter"] = [];
    }
    private $store = $_SESSION["ers-rate-limiter"];

    public function limit(Rate $rate): void
    {
        $identifier = strval(session_id());
        $key = $this->key($identifier, $rate->getInterval());

        $current = $this->hit($key, $rate);

        if ($current > $rate->getOperations()) {
            throw LimitExceeded::for($identifier, $rate);
        }
    }

    public function limitSilently(Rate $rate): Status
    {
        $identifier = strval(session_id());
        $key = $this->key($identifier, $rate->getInterval());

        $current = $this->hit($key, $rate);

        return Status::from(
            $identifier,
            $current,
            $rate->getOperations(),
            $this->store[$key]['reset_time']
        );
    }

    private function key(string $identifier, int $interval): string
    {
        return "$identifier:$interval:" . floor(time() / $interval);
    }

    private function hit(string $key, Rate $rate): int
    {
        if (!isset($this->store[$key])) {
            $this->store[$key] = [
                'current' => 1,
                'reset_time' => time() + $rate->getInterval(),
            ];
        } elseif ($this->store[$key]['current'] <= $rate->getOperations()) {
            $this->store[$key]['current']++;
        }

        return $this->store[$key]['current'];
    }
}

