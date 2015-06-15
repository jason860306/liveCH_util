INCLUDE=
LIBS=
MACRO=
CFLAGS=-g -Wall -O0 ${MACRO}
#-gstabs+

BINARY=$(patsubst %.cpp,%,$(wildcard *.cpp))
OBJECT=$(BINARY:%=%.o)
BIN=liveCH_util

.PHONE: all clean install test
all:$ $(BIN)

$(BIN):$(OBJECT)
	@echo compiling $@
	$(CXX) $^ -o $@ $(INCLUDE) $(LIBS) $(CFLAGS)

$(OBJECT):
	@echo compiling $(@:%.o=%.cpp)
	$(CXX) -c $(@:%.o=%.cpp) $(INCLUDE) $(CFLAGS)

clean:
	@rm -rf ${BINARY} 
	@rm -rf $(OBJECT)
	@rm -rf $(BIN)
	@rm -rf *~

install:
	@cp *.h ${SERVER_ROOT}/include

test:
	@echo "BIN: " $(BIN)
	@echo "BINARY: " $(BINARY)
	@echo "OBJECT: " $(OBJECT)
