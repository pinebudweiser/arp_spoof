TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    mytools.c
LIBS += -lpcap
LIBS += -pthread

HEADERS += \
    mytools.h \
    myheader.h
