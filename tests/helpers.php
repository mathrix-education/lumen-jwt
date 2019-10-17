<?php

declare(strict_types=1);

if (!function_exists('mkdirp')) {
    function mkdirp(string $path)
    {
        if (file_exists($path)) {
            return;
        }

        mkdir($path, 0755, true);
    }
}
