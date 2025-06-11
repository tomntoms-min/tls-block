CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11
LDFLAGS = -lpcap

TARGET = tls-block
SRCS = tls-block.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
