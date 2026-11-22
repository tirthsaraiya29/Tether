CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?= -shared -Wl,-z,relro,-z,now

TARGET = pam_tether.so
TEST_TARGET = test_pam_tether

all: $(TARGET) $(TEST_TARGET)

$(TARGET): pam_tether.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pam_tether.c -lpam

$(TEST_TARGET): test_pam_tether.c pam_tether.c
	$(CC) $(CFLAGS) -o $@ test_pam_tether.c pam_tether.c -lpam

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TARGET) $(TEST_TARGET) *.o

.PHONY: all test clean
