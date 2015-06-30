#-------------------------------------------------
#
# Project created by QtCreator 2015-06-06T16:13:40
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = FileCryptography
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    crypto.cpp

HEADERS  += mainwindow.h \
    crypto.h

FORMS    += mainwindow.ui

unix:!macx: LIBS += -L$$PWD/../openssl-1.0.2a/ -lcrypto

INCLUDEPATH += $$PWD/../openssl-1.0.2a/include
DEPENDPATH += $$PWD/../openssl-1.0.2a/include

unix:!macx: PRE_TARGETDEPS += $$PWD/../openssl-1.0.2a/libcrypto.a
