# ADA Wrapper Tests

This directory contains tests for the ADA wrapper.

## Running the Tests

To run the tests using [alire](https://alire.ada.dev/), execute the following command from this directory:

```
alr run
```

This will build and run all ADA wrapper tests.

## Running the Tests with Valgrind

After building the tests with `alr build`, you can run them with valgrind using the provided suppressions file:

```
valgrind --track-origins=yes --leak-check=full --suppressions=valgrind.supp ./bin/tests
```
