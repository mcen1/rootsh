package main

import (
	"flag"
	"io"
        "log"
	"log/syslog"
	"os"
	"os/exec"
        "bufio"
	"fmt"
        "strings"
        "bytes"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	logfile string
	rsyslog string
)

func main() {
	fmt.Println("WARNING: Only authorized user access is allowed. All activity in this session will be monitored and evaluated.")
	conffile, err := os.Open("/etc/rootsh.conf")
	if err != nil {
	        log.Fatal(err)
	}
	defer conffile.Close()
	var nlogfile string
	var rootshell string
        nlogfile="/dev/null"
        rootshell="/bin/bash"
	scanner := bufio.NewScanner(conffile)
	for scanner.Scan() {
                if (strings.Contains(scanner.Text(), "logfile=")) {
                  nlogfile=strings.Split(scanner.Text(), "=")[1]
                }
                if (strings.Contains(scanner.Text(), "shell=")) {
                  rootshell=strings.Split(scanner.Text(), "=")[1]
                }
	}

	if err := scanner.Err(); err != nil {
	        log.Fatal(err)
	}
	flag.StringVar(&logfile, "logfile", nlogfile, "Path to the log file.")

	flag.Parse()

	cmd := exec.Command(rootshell)
	tty, err := pty.Start(cmd)
	if err != nil {
		panic(err)
	}
	defer tty.Close()

	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(0, oldState)

	file, err := os.OpenFile(logfile, os.O_RDWR|os.O_APPEND, 0775)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	logwriter,err := syslog.New(syslog.LOG_INFO, "rootsh")
	if err != nil {
		panic(err)
	}
	defer logwriter.Close()
        l := &Logger{logwriter: logwriter, buffer: &bytes.Buffer{}}

	mw := io.MultiWriter(os.Stdout, file, l)

	go io.Copy(tty, os.Stdin)
	io.Copy(mw, tty)
}
