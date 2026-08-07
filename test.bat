@echo off
rem Build and run tests in debug mode
xmake f -m debug -c
xmake build testsuite
xmake run testsuite
