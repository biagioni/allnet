#!/usr/local/bin/Python
"""Simple GUI for AllNet xchat programs"""
import Tkinter
import sys
import subprocess

# note: if we want to run xchatr in here, this link might help:
# http://stackoverflow.com/questions/665566/python-tkinter-shell-to-gui

if len(sys.argv) != 2:
	print 'usage: %s contact-name' % sys.argv [0]
	sys.exit (1)

contact = sys.argv [1]

root = Tkinter.Tk()
root.title("xchat")

text  = Tkinter.Text(root, width=20, height=5, highlightthickness=2)

input = ''

def reportEvent(event):
    global input
    if event.keysym == 'Return':
        print 'keysym was return, text was %s' % input
#	result = subprocess.check_output(['/bin/echo', '-n', 'xchats', contact, input]);
	result = subprocess.check_output(['./xchats', contact, input]);
        input = ''
        text.insert ('end', '\n' + result)
    elif event.keysym == 'space':
        input = input + ' '
    elif event.keysym == 'comma':
        input = input + ','
    elif event.keysym == 'minus':
        input = input + '-'
    elif event.keysym == 'exclam':
        input = input + '!'
    elif event.keysym == 'question':
        input = input + '?'
    elif event.keysym == 'Shift_L':
	pass
    elif event.keysym == 'BackSpace':
        if len(input) > 1:
            input = input[0:len(input) - 1]
	else:
            input = ''
    else:
        # print 'keysym was %s' % event.keysym
        input = input + event.keysym
    # print 'keysym=%s, keysym_num=%s' % (event.keysym, event.keysym_num)

text.bind('<KeyPress>', reportEvent)

text.pack(expand=1, fill="both")
text.focus_set()

root.mainloop()
