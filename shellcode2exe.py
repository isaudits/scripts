#!/usr/bin/env python

# Shellcode to executable converter
# Copyright (c) 2009-2015, Mario Vilas
# All rights reserved.
#
# Tweaked by Anand Sastry in 2/2010 and 12/2011 to allow the user to provide
# shellcode as a \x encoded string on the command-line, if the user
# doesn't wish to supply a file name that contains raw shellcode.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# Requires InlineEgg by CORE Security Technologies
# http://oss.coresecurity.com/projects/inlineegg.html
try:
    from inlineegg import exelib
except ImportError:
    exelib = None

# Shellcode to executable converter
class ShellcodeToExecutable(object):

    # List of supported OS
    os_list = (
        'windows',
        'linux',
        'freebsd',
        'openbsd',
        'solaris',
    )

    # List of supported ARCH
    arch_list = (
        'i386',
        'powerpc',
        'sparc',
        'arm',
    )

    def __init__(self, shellcode, os='windows', arch='i386'):
        method = getattr(self, 'build_%s_%s' % (os, arch), None)
        if method is None:
            raise NotImplementedError, "unsupported platform: %s on %s" % (os, arch)
        method(shellcode)

    def __str__(self):
        return self.bytes()

    def bytes(self):
        return self.__program.bytes()

    def build_windows_i386(self, shellcode):
        if len(shellcode) > 4096:
            raise RuntimeError("Payloads over 4k for EXE files are not supported")
        self.__program = exelib.PEProgram()
        self.__program.addCode(shellcode)

    def build_linux_i386(self, shellcode):
        self.__program = exelib.Elf32Program()
        self.__program.setArch(self.__program.ARCH_I386)
        self.__program.addCode(shellcode)

    def build_linux_sparc(self, shellcode):
        self.__program = exelib.Elf32Program()
        self.__program.setArch(self.__program.ARCH_SPARC)
        self.__program.addCode(shellcode)

    def build_linux_powerpc(self, shellcode):
        self.__program = exelib.AOutProgram()
        self.__program.setArch(self.__program.MID_POWERPC)
        self.__program.setCode(shellcode)

    def build_linux_arm(self, shellcode):
        self.__program = exelib.AOutProgram()
        self.__program.setArch(self.__program.MID_ARM6)
        self.__program.setCode(shellcode)

    def build_solaris_i386(self, shellcode):
        self.__program = exelib.Elf32Program()
        self.__program.setArch(self.__program.ARCH_I386)
        self.__program.addCode(shellcode)

    def build_solaris_sparc(self, shellcode):
        self.__program = exelib.Elf32Program()
        self.__program.setArch(self.__program.ARCH_SPARC)
        self.__program.addCode(shellcode)

    def build_freebsd_i386(self, shellcode):
        self.__program = exelib.Elf32Program()
        self.__program.setArch(self.__program.ARCH_I386)
        self.__program.header.ei_osabi = exelib.ELFOSABI_FREEBSD
        self.__program.addCode(shellcode)

    def build_freebsd_sparc(self, shellcode):
        self.__program = exelib.Elf32Program()
        self.__program.setArch(self.__program.ARCH_SPARC)
        self.__program.header.ei_osabi = exelib.ELFOSABI_FREEBSD
        self.__program.addCode(shellcode)

    def build_freebsd_arm(self, shellcode):
        self.__program = exelib.AOutProgram()
        self.__program.setArch(self.__program.MID_ARM6)
        self.__program.setCode(shellcode)

    def build_openbsd_i386(self, shellcode):
        self.__program = exelib.AOutProgram()
        self.__program.setArch(self.__program.ARCH_I386)
        self.__program.setCode(shellcode)

    def build_openbsd_sparc(self, shellcode):
        self.__program = exelib.AOutProgram()
        self.__program.setArch(self.__program.MID_SPARC)
        self.__program.setCode(shellcode)

    def build_openbsd_powerpc(self, shellcode):
        self.__program = exelib.AOutProgram()
        self.__program.setArch(self.__program.MID_POWERPC)
        self.__program.setCode(shellcode)

    def build_openbsd_arm(self, shellcode):
        self.__program = exelib.AOutProgram()
        self.__program.setArch(self.__program.MID_ARM6)
        self.__program.setCode(shellcode)

# Main function to run when invoked from the command line
def main(argv):
    from os import path
    import optparse

    # Banner
    print "Shellcode to executable converter"
    print "by Mario Vilas (mvilas at gmail dot com)"
    print

    # Configure the command line parser
    usage  = "\n\t%%prog payload.bin [payload.exe]\n\t\t[--arch=%s]\n\t\t[--os=%s]\n\t\t[-c Allow for ascii shellcode as a cmd line parameter]\n\t\t[-s Allows for ascii shellcode in file]"
    usage  = usage % ( '|'.join(ShellcodeToExecutable.arch_list), '|'.join(ShellcodeToExecutable.os_list) )
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-a", "--arch", metavar="ARCH",
                      help="target architecture [default: i386]")
    parser.add_option("-o", "--os", metavar="OS",
                      help="target operating system [default: windows]")
    parser.add_option("-c", "--asciicmd", action="store_true", dest="asciicmd",
                  help="enable ascii entry in input file")
    parser.add_option("-s", "--asciifile", action="store_true", dest="asciifile",
                      help="enable ascii entry in command line")
    parser.set_defaults(arch='i386', os='windows')

    # Parse the command line arguments
    if len(argv) == 1:
        argv = argv + ['-h']
    options, parameters = parser.parse_args(argv)
    parameters = parameters[1:]

    # Now's a good time to show an error if InlineEgg is missing
    if exelib is None:
        parser.error("missing module:\n    InlineEgg (http://oss.coresecurity.com/projects/inlineegg.html)")

    # Validate the command line arguments
    if len(parameters) < 1:
        parser.error("missing parameter: input file")
    options.arch = options.arch.strip().lower()
    options.os   = options.os.strip().lower()
    if options.arch not in ShellcodeToExecutable.arch_list:
        parser.error("unknown architecture: %s" % options.arch)
    if options.os not in ShellcodeToExecutable.os_list:
        parser.error("unknown operating system: %s" % options.os)
    if len(parameters) < 2 and options.asciicmd is None:
        if options.os == 'windows':
            parameters.append('%s%s%s' % (path.splitext(parameters[0])[0], path.extsep, 'exe'))
        else:
            parameters.append(path.splitext(parameters[0])[0])
        if parameters[1] == parameters[0]:
            parameters[1] = '%s_executable%s' % path.splitext(parameters[0])

    try:

        # Get the shellcode
        if options.asciicmd is True:
            print "Treating first parameter as \\x encoded shellcode"
            shellcode = parameters[0]
            shellcode = shellcode.decode("string-escape")
        elif options.asciifile is True:
            print "Reading string shellcode from file %s" % parameters[0]
            shellcode = open(parameters[0], 'rb').read()
            shellcode = shellcode.decode("string-escape")
        else:
            print "Reading raw shellcode from file %s" % parameters[0]
            shellcode = open(parameters[0], 'rb').read()

        # Convert the shellcode to an executable file
        print "Generating executable file"
        executable = ShellcodeToExecutable(shellcode, options.os, options.arch)
        if len(parameters) < 2:
            filename = "payload.exe"
        else:
            filename = parameters[1]
        print "Writing file %s" % filename
        bytes = executable.bytes()
        open(filename, 'w+b').write(bytes)
        print "Done."

    except Exception, e:
##        raise   # XXX DEBUG
        parser.error(str(e))

# Run main() when invoked from the command line
if __name__ == "__main__":
    import sys
    main(sys.argv)