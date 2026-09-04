PREFIX=/usr/local
KA9Q_RADIO_DIR:=./ALT_SRC

FILES = config.h  config_paths.h  filter.h  iir.h  misc.c  misc.h  multicast.c  multicast.h  osc.h  radio.h  rtp.c  rtp.h  status.c  status.h  window.h

# use alternate source copies if KA9Q_RADIO_DIR not found
ifeq ($(wildcard ../ka9q-radio),)
else
copy-files:
	mkdir -p $(KA9Q_RADIO_DIR)
	$(foreach file,$(FILES),cp ../ka9q-radio/src/$(file) $(KA9Q_RADIO_DIR)/;)
	$(MAKE) all
endif

CC = gcc
CFLAGS = -std=gnu11 -Wall -O3 -D_GNU_SOURCE=1

INCLUDES=-isystem $(KA9Q_RADIO_DIR)
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
	rm -rf $(DEPS) $(OBJS) $(KA9Q_RADIO_OBJS) $(TARGET) ALT_SRC/*.o

.PHONY: all clean
