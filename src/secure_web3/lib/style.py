import colored


class PrettyText:
    def __init__(self, verbosity):
        self.verbosity = verbosity

    def debug(self, data):
        if self.verbosity >= 2:
            print(colored.fore.WHITE+ '[' + colored.fore.GREY_3 + '%' + colored.fore.WHITE + '] ' + colored.style.RESET +
                  str(data))

    def status(self, data):
        print(
            colored.fore.DARK_OLIVE_GREEN_1A + '[' + colored.fore.LIGHT_STEEL_BLUE_1 + 'i' +
            colored.fore.DARK_OLIVE_GREEN_1A + '] ' + colored.style.RESET + str(data))

    def verbose(self, data):
        if self.verbosity >= 1:
            print(colored.fore.LIGHT_YELLOW + '[' + colored.fore.MAGENTA + '*' + colored.fore.LIGHT_YELLOW + ']' +
                  colored.style.RESET + str(data))

    def normal(self, data):
        print(colored.fore.LIGHT_BLUE + colored.style.BOLD + '[' + colored.fore.RED + '+'
              + colored.fore.LIGHT_BLUE + '] ' + colored.style.RESET + str(data))

    def error(self, data):
        print(
            colored.fore.RED_1 + colored.style.BOLD + '[' + colored.fore.WHITE + '!' \
            + colored.fore.RED_1 + '] '+ colored.style.RESET + str(data))

    def good(self, data):
        print(
            colored.fore.LIGHT_GREEN + colored.style.BOLD + '[' + colored.fore.MAGENTA + '~' \
            + colored.fore.LIGHT_GREEN +  '] ' + colored.style.RESET + str(data))

    def warning(self, data):
        print(colored.fore.VIOLET + colored.style.BOLD + '[' + colored.fore.VIOLET + \
              '*' + colored.fore.VIOLET + '] ' + colored.style.RESET + str(data))