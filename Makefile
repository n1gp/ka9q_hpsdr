PREFIX=/usr/local
KA9Q_RADIO_DIR=../ka9q-radio/src
ALT_SRC=./ALT_SRC

# use alternate source copies if KA9Q_RADIO_DIR not found
ifeq ($(wildcard ../ka9q-radio/src),)
	KA9Q_RADIO_DIR=./ALT_SRC
else
	KA9Q_RADIO_DIR=../ka9q-radio/src
endif

CC = gcc
CFLAGS = -std=gnu11 -Wall -O3 -D_GNU_SOURCE=1

INCLUDES=-I$(KA9Q_RADIO_DIR)
KA9Q_RADIO_OBJS=$(KA9Q_RADIO_DIR)/multicast.o $(KA9Q_RADIO_DIR)/status.o $(KA9Q_RADIO_DIR)/misc.o $(KA9Q_RADIO_DIR)/rtp.o

LIBS = -lrt -lm -lpthread -lbsd

CPPFLAGS=$(INCLUDES)

TARGET = ka9q_hpsdr

DEPENDDIR = .
DEPENDFLAGS = -MM

SRCS = ka9q_hpsdr.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

DEPS = $(patsubst %.o,$(DEPENDDIR)/%.d,$(OBJS))
-include $(DEPS)

$(DEPENDDIR)/%.d: %.c $(DEPENDDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPENDFLAGS) $(INCLUDES) $< >$@

$(TARGET): $(OBJS) $(KA9Q_RADIO_OBJS)
	$(CC) $(OBJS) $(KA9Q_RADIO_OBJS) $(INCLUDES) $(LIBS) -o $(TARGET)

clean:
	rm -f $(DEPS) $(OBJS) $(KA9Q_RADIO_OBJS) $(TARGET) ALT_SRC/*.o

.PHONY: all clean
