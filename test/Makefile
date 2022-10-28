CC = g++
CC_FLAG = 
CC_FLAG += -fPIC
CC_FLAG += -g3 -w
#CC_FLAG += -gdwarf-2 
CC_FLAG += -O0
CC_FLAG += -Wall 

LD = ld
AR = ar

ARCHITECTURE = $(shell uname -m)
ifeq (${ARCHITECTURE},x86_64)
GNU_LIB_PATH:=x86_64
else
GNU_LIB_PATH:=i386
endif

INCLUDE=-I..  -I/usr/include/glib-2.0/ -I/usr/lib/${GNU_LIB_PATH}-linux-gnu/glib-2.0/include `pkg-config --cflags glib-2.0`
LIBRARIES=-lgmp -lgmpxx -lpthread  -L /usr/lib  -lssl -lcrypto -lglib-2.0 `pkg-config --libs glib-2.0`


RSP_DIR = ../../SudoPPA/sdk/api
LIB_RSP = -L$(RSP_DIR) -l:librsp.a

CAP_DIR = ../../SudoPPA/sdk/cap
LIB_CAP = -L$(CAP_DIR) -l:libcap-static.a

SDF_DIR = ../../SudoPPA/library/sdf
LIB_SDF = -L$(SDF_DIR) -l:libsdf-static.a

PSI_DIR = ../lib
LIB_PSI = -L$(PSI_DIR) -l:libwhpsi.a

MIRACL_DIR = ../lib
MIRACL_LIB = -L$(MIRACL_DIR) -l:libmiracl.a

INC =
INC += $(INCLUDE)

SRC = $(wildcard ./*.cpp)

LIB =
LIB += $(LIB_PSI)
LIB += $(MIRACL_LIB)
LIB += $(LIB_SDF)
LIB += $(LIB_CAP)
LIB += $(LIB_RSP)
LIB += $(LIBRARIES)
LIB += -ldl -lpthread

OBJ = $(patsubst %cpp, %o, $(SRC))


OBJECTS_PSI = psi_test.o
OBJECTS_PSI_STEP = psi_ax_test.o
OBJECTS_PIR = pir_test.o

target = test-psi.exe
target-step = test-psi-step.exe
target-pir = test-pir.exe

all : $(target) $(target-step) $(target-pir)

$(target) : $(OBJ)
	$(CC) $(CC_FLAG) -o $@ $(OBJECTS_PSI) $(LIB)

$(target-step) : $(OBJ)
	$(CC) $(CC_FLAG) -o $@ $(OBJECTS_PSI_STEP) $(LIB)

$(target-pir) : $(OBJ)
	$(CC) $(CC_FLAG) -o $@ $(OBJECTS_PIR) $(LIB)

# .SUFFIXES: .c.o
# .c.o:
# 	$(CC) $(CC_FLAG) $(INC) -c $*.c -o $*.o

%.o:%.cpp
	$(CC) $(CC_FLAG) ${INC} $(LIB) -fPIC -o $@ -c $<

.PHONY : clean
clean :
	@echo "Remove compile out..."
	rm -f *.o $(target) $(target-step);

