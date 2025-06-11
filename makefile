CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11 -pthread
LDFLAGS = -lpcap -pthread

TARGET = tls-block
SRCS = tls-block.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
