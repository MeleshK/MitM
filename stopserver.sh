#!/bin/bash

#terminate mitmdump if already running.
try:
  kill "$(pgrep mitmdump)"
