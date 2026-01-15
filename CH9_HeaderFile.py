import os, time

################################## FG COLOR DEFINITIONS ##################################
class bcolors:
    # pure colors...
    GREY        = '\033[90m'
    RED         = '\033[91m'
    GREEN       = '\033[92m'
    YELLOW      = '\033[93m'
    BLUE        = '\033[94m'
    PURPLE      = '\033[95m'
    CYAN        = '\033[96m'
    # color styles...
    HEADER      = '\033[96m\033[1m'
    MSG         = '\033[90m'
    QUESTION    = '\033[95m\033[3m'
    COMMENT     = '\033[96m'
    IMPLEMENTED = '\033[92m' + '[IMPLEMENTED] ' +'\033[96m'
    TODO        = '\033[94m' + '[TO DO] ' +'\033[96m'
    WARNING     = '\033[93m'
    ERROR       = '\033[91m\033[1m'
    ENDC        = '\033[0m'    # RECOVERS DEFAULT TEXT COLOR
    NORMAL      = '\033[1m'
    BOLD        = '\033[2m'
    ITALICS     = '\033[3m'
    UNDERLINE   = '\033[4m'
    BLINK       = '\033[5m'
    HIGHLIGHT   = '\033[7m'
    # ALICE-BOB-CHUCK color styles...
    ALICE       = '\033[92m' # green
    BOB         = '\033[93m' # yellow
    CHUCK       = '\033[94m' # blue

    SERVER      = '\033[92m' # green
    CLIENT      = '\033[93m' # yellow
    SYSTEM      = '\033[96m' # cyan
    OWNER       = '\033[96m' # cyan
    SENDER      = '\033[92m' # green
    RECEIVER    = '\033[93m' # yellow

    def disable(self):
        self.HEADER     = ''
        self.OKBLUE     = ''
        self.OKGREEN    = ''
        self.WARNING    = ''
        self.FAIL       = ''
        self.ENDC       = ''

################################### CLEARSCEEN + LINES ###################################
def screen_clear():
   # for mac and linux platforms (here, os.name is 'posix')
   if os.name == 'posix':
      _ = os.system('clear')
   else:
      # for windows platfrom
      _ = os.system('cls')

def drawLine(lineLength,lineCharacter):

    LINE          = ''
    consecutiveLineCharacters    = lineCharacter
    for i in range(lineLength):
            consecutiveLineCharacters    = consecutiveLineCharacters  + lineCharacter
    LINE          = LINE + consecutiveLineCharacters
    return(LINE)

LINELENGTH  = 80
EQLINE      = drawLine(LINELENGTH,'=')
MINUSLINE   = drawLine(LINELENGTH,'-')
PLUSLINE    = drawLine(LINELENGTH,'+')
##########################################################################################

def getLocalTime():
    t = time.localtime()    # for local time    (GMT+3)
    return("[Current Time: " + str(t.tm_hour) + "h" + str(t.tm_min) + "m" + str(t.tm_sec) + "s] ") 

def getTimeInMilliseconds():
        t = round(time.time() * 1000) # computation of current time in milliseconds
        return(int(t)) 

def print_msg(name,msg):  

    if name == "ALICE":
        print(bcolors.ALICE + msg + bcolors.ENDC)
    elif name == "BOB":
        print(bcolors.BOB + msg + bcolors.ENDC)
    elif name == "CHUCK":
        print(bcolors.CHUCK + msg + bcolors.ENDC)
    elif name == "SERVER":
        print(bcolors.SERVER + msg + bcolors.ENDC)
    elif name == "CLIENT":
        print(bcolors.CLIENT + msg + bcolors.ENDC)
    elif name == "SYSTEM":
        print(bcolors.SYSTEM + msg + bcolors.ENDC)
    elif name == "SENDER":
        print(bcolors.SENDER + msg + bcolors.ENDC)
    elif name == "RECEIVER":
        print(bcolors.RECEIVER + msg + bcolors.ENDC)
    elif name == "OWNER":
        print(bcolors.OWNER + msg + bcolors.ENDC)
    else:
        print(bcolors.WARNING + msg + bcolors.ENDC)

def print_function_preamble(msg):

    #print(msg)
    return