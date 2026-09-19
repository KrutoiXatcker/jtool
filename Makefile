CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -pthread

TARGET := jtool
SOURCES := $(shell find core modules -type f -name '*.cpp')

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -Icore $(SOURCES) -o $(TARGET)

clean:
	$(RM) $(TARGET)
