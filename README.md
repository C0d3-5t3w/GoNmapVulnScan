# GoNmapVulnScan

Lightly scans entire network for vulnerabilities.

# Setup

Download this repo and put it into your go project forlder.

# Navigate to the folder and run:

sudo go get github.com/gocarina/gocsv

# After that either run:

sudo go run main.go

# Or:

sudo go build main.go 

(if you do this you can just double click the executable in your file explorer or run: sudo ./main)

# What happens:

Lightly scans entire network for basic vulnerabilities and save them to the users home folder (~) in
a directory called vulnerabilities_dir

/home/username/vulnerabilities_dir
or
~/vulnerabilities_dir
