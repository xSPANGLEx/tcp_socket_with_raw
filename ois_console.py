#!/usr/bin/env python
import curses
import shutil
import time


class Screen:

    def __init__(self, screen=1):
        self.lock = False
        self.std_scr = curses.initscr()
        self.screen_initialize()
        term_size = shutil.get_terminal_size()
        self.term_width = term_size.columns
        self.term_height = term_size.lines
        self.screen = screen
        self.output_scr = []
        self.output_pos = []
        for i in range(screen):
            if i == screen - 1:
                self.output_scr.append(curses.newpad(self.term_height-1, int(self.term_width/screen) + screen % 2))
            else:
                self.output_scr.append(curses.newpad(self.term_height-1, int(self.term_width/screen)))
            self.output_pos.append([0, 0])
            self.output_scr[i].scrollok(1)
            self.refresh(screen=i)
        self.input_scr = curses.newpad(1, self.term_width)

    def screen_initialize(self):
        curses.noecho()
        curses.cbreak()

    def screen_finalize(self):
        curses.echo()
        curses.nocbreak()
        curses.endwin()

    def print(self, data, screen=0):
        while self.lock:
            time.sleep(0.05)
        self.lock = True
        scr = self.output_scr[screen]
        scr_pos = self.output_pos[screen]
        for char in list(data):
            char = chr(char)
            if char == "\n":
                if scr_pos[0] == scr.getmaxyx()[0] - 1:
                    scr.addch(scr_pos[0], scr_pos[1], char)
                else:
                    scr.addch(scr_pos[0], scr_pos[1], char)
                    scr_pos[0] += 1
                scr_pos[1] = 0
            else:
                scr.addch(scr_pos[0], scr_pos[1], char)
                scr_pos[1] += 1
            if scr_pos[1] == scr.getmaxyx()[1] - 1:
                scr.addch(scr_pos[0], scr_pos[1], "\n")
                scr_pos[1] = 0
                scr_pos[0] += 1
            if scr_pos[0] == scr.getmaxyx()[0]:
                scr_pos[0] -= 1
        self.refresh(screen)
        self.lock = False

    def refresh(self, screen=0):
        scr = self.output_scr[screen]
        root_width = 0
        for i in range(screen):
            root_width += self.output_scr[i].getmaxyx()[1]
        root_pos = [0, root_width]
        width = int(self.term_width/self.screen * (screen + 1))
        scr.hline(self.term_height-2, 0, "=", scr.getmaxyx()[1])
        if screen != self.screen-1:
            scr.vline(0, scr.getmaxyx()[1]-1, "|", self.term_height-2)
        scr.refresh(0, 0, root_pos[0], root_pos[1], self.term_height-2, width)

    def row_clear(self, screen=0):
        while self.lock:
            time.sleep(0.05)
        self.lock = True
        self.lock = True
        scr = self.output_scr[screen]
        scr_pos = self.output_pos[screen]
        for i in range(scr_pos[1]):
            scr.addch(scr_pos[0], i, " ")
        scr.addch(scr_pos[0], 0, "\r")
        scr_pos[1] = 0
        self.refresh(screen)
        self.lock = False

    def row_back(self, screen=0):
        scr_pos = self.output_pos[screen]
        scr_pos[0] -= 1
        if scr_pos[0] < 0:
            scr_pos[0] = 0
        self.refresh(screen)

    def clear(self, screen=0):
        scr = self.output_scr[screen]
        width = scr.getmaxyx()[1]
        height = scr.getmaxyx()[0]
        for i in range(height):
            if i == height-1:
                width -= 1
            for j in range(width):
                scr.addch(i, j, " ")
        self.output_pos[screen] = [0, 0]
        self.refresh(screen)

    def input(self):
        for i in range(self.term_width-1):
            self.input_scr.addch(0, i, " ")
        self.input_scr.move(0, 0)
        self.input_scr.refresh(0, 0, self.term_height-1, 0, self.term_height-1, self.term_width-1)
        result = []
        input_count = 0
        while 1:
            char_row = self.input_scr.getch()
            char = chr(char_row)
            if char == "\n":
                break
            if char_row == curses.KEY_BACKSPACE or char_row == 127:
                if input_count != 0:
                    input_count -= 1
                    self.input_scr.addch(0, input_count, " ")
                    self.input_scr.move(0, input_count)
                    self.input_scr.refresh(0, 0, self.term_height-1, 0, self.term_height-1, self.term_width-1)
                    result.pop()
                    continue
                else:
                    continue
            self.input_scr.addch(0, input_count, char)
            self.input_scr.refresh(0, 0, self.term_height-1, 0, self.term_height-1, self.term_width-1)
            result.append(char)
            input_count += 1
        return "".join(result)
