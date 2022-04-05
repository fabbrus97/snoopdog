#!/bin/bash

rm accel.out
adb pull /sdcard/snoopdogg/accel.out accel.raw
sed 's/.*(//g' accel.raw | sed 's/)/,/g' | tee accel.out
