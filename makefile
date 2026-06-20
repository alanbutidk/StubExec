CC = cc
CFLAGS = -Wall

ifeq ($(OS),Windows_NT)
	EXE_EXT := .exe
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		EXE_EXT :=
	endif
endif

TARGET := Stub$(EXE_EXT)

all: $(TARGET)

$(TARGET): Stubs/StubSrc.c
	$(CC) $(CFLAGS) -o Stubs/$(TARGET) Stubs/StubSrc.c

clean:
	rm -f Stubs/$(TARGET)