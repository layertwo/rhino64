package main

import (
    "github.com/miekg/dns"
    "log"
    "net"
)

var (
    prefix = net.IP{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

func main() {
    dns.HandleFunc(".", handleRequest)
    err := dns.ListenAndServe(":53", "udp6", nil)
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}

func makeRequest(name string, qtype uint16) []dns.RR {

    c := new(dns.Client)
    log.Printf("querying %s record for %s\n", dns.TypeToString[qtype], name)

    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(name), qtype)
    m.RecursionDesired = true

    r, _, err := c.Exchange(m, net.JoinHostPort("8.8.8.8", "53"))
    if r == nil {
        log.Fatalf("error: %s\n", err.Error())
    }

    if r.Rcode != dns.RcodeSuccess {
        log.Fatalf("invalid answer name for query %s\n", name)
    }

    return r.Answer
}

func handleRequest(w dns.ResponseWriter, req *dns.Msg) {

    m := new(dns.Msg)
    m.SetReply(req)

    for _, q := range m.Question {

        answers := makeRequest(q.Name, q.Qtype)
        if len(answers) > 0 {
            log.Printf("found %v answer(s) for %s", len(answers), q.Name)
            for _, a := range answers {
                m.Answer = append(m.Answer, a)
            }
        } else {
            log.Printf("did not find %s answer for %s", dns.TypeToString[q.Qtype], q.Name)

            if q.Qtype == dns.TypeAAAA {
                log.Printf("generating synthetic IPv6 addr for %s", q.Name)

                answers := makeRequest(q.Name, dns.TypeA)
                if len(answers) > 0 {
                    log.Printf("found %v answers for %s", len(answers), q.Name)

                    for _, a := range answers {
                        record := a.(*dns.A)
                        rr := &dns.AAAA{
                            Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: record.Hdr.Class, Ttl: record.Hdr.Ttl},
                            AAAA: makeSyntheticIPv6(record.A),
                        }
                        m.Answer = append(m.Answer, rr)
                    }
                }
            }
        }
    }

    buf, _ := m.Pack()
    w.Write(buf)

}

func makeSyntheticIPv6(ip net.IP) net.IP {

    synth := prefix
    synth[12] = ip[0]
    synth[13] = ip[1]
    synth[14] = ip[2]
    synth[15] = ip[3]

    return synth

}
