#!/bin/bash

git describe --tags --abbrev=10 --dirty 2>/dev/null || echo "unknown"