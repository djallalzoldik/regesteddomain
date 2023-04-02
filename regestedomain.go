package main

import (
        "bufio"
        "fmt"
        "net"
        "os"
        "strings"
        "time"

        "github.com/domainr/whois"
)

func main() {
        scanner := bufio.NewScanner(os.Stdin)

        client := whois.Client{
                Timeout: 5 * time.Second,
                Dial: func(network, addr string) (net.Conn, error) {
                        return net.DialTimeout(network, addr, 5*time.Second)
                },
        }

        for scanner.Scan() {
                domain := scanner.Text()
                isRegistered, err := checkDomainRegistration(domain, &client)
                if err != nil {
                        fmt.Printf("Error checking %s: %s\n", domain, err)
                } else {
                        if isRegistered {
                                fmt.Printf("%s is registered.\n", domain)
                        } else {
                                fmt.Printf("%s is not registered.\n", domain)
                        }
                }
        }

        if err := scanner.Err(); err != nil {
                fmt.Fprintln(os.Stderr, "Error reading from stdin:", err)
        }
}

func checkDomainRegistration(domain string, client *whois.Client) (bool, error) {
        req, err := whois.NewRequest(domain)
        if err != nil {
                return false, err
        }

        res, err := client.Fetch(req)
        if err != nil {
                return false, err
        }

        isRegistered := !strings.Contains(res.String(), "No match for")
        return isRegistered, nil
}
