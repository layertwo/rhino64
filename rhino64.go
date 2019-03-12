package main

import (
    "github.com/miekg/dns"
    "fmt"
    "net"
    "log"
    "os"
    )

var (
    prefix = net.IP{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

func main() {
    c := new(dns.Client)

    uri := dns.Fqdn(os.Args[1])
    answers  := makeDNSRequest(c, dns.TypeAAAA, uri)
    if len(answers) >= 1 {
        log.Printf("Got IPv6 addresses for %s", uri)

        for _, a := range answers {
            fmt.Printf(a.(*dns.AAAA).AAAA.String())
        }
    } else {
        answers = makeDNSRequest(c, dns.TypeA, uri)
        for _, a := range answers {
            fmt.Printf(a.(*dns.A).A.String())
        }
    }

}

func makeDNSRequest(c *dns.Client, rtype uint16, uri string) []dns.RR {

    log.Printf("querying %s for %s\n", rtype, uri)

    m := new(dns.Msg)
    m.SetQuestion(uri, rtype)
    m.RecursionDesired = true

    r, _, err := c.Exchange(m, net.JoinHostPort("8.8.8.8", "53"))
    if r == nil {
        log.Fatalf("error: %s\n", err.Error())
    }

    if r.Rcode != dns.RcodeSuccess {
        log.Fatalf("invalid answer name for query %s\n", uri)
    }

    return r.Answer
}
