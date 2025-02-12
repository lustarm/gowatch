package load

import (
	"bufio"
	"gowatch/modules/packet"
	"os"
)

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

    return nil
}

