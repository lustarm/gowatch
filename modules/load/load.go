package load

import (
	"bufio"
    "log"
	"os"

	"gowatch/modules/packet"
)

/*
    This function will load all of our files that we need.

    This includes files such as bad ips, config, and more
    as we move along with the project.
*/
func Load() error {
    // ! read file
    f, err := os.Open("./data/Bad-IPs.txt")

    if err != nil {
        return err
    }

    defer f.Close()

    scanner := bufio.NewScanner(f)

    for scanner.Scan() {
        packet.MarkBad(scanner.Text())
        // log.Println(scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return err
    }

    log.Println("Loaded list of IPs")

    return nil
}

