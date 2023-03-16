package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
)

type Credential struct {
	ApiVersion string `json:"apiVersion"`
	Data       struct {
		CA        []byte `json:"ca.crt"`
		Namespace string `json:"namespace"`
		Token     string `json:"token"`
	} `json:"data"`
	Kind     string `json:"kind"`
	Metadata struct {
		Annotations struct {
			Name string `json:"kubernetes.io/service-account.name"`
			ID   string `json:"kubernetes.io/service-account.uid"`
		} `json:"annotations"`
		Timestamp       string `json:"creationTimestamp"`
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion"`
		Uid             string `json:"uid"`
	} `json:"metadata"`
	Type string `json:"type"`
}

func (c *Credential) Write(b []byte) (n int, err error) {
	var buf bytes.Buffer
	len, err := buf.Write(b)
	if err != nil {
		return 0, err
	}
	c.Data.CA = buf.Bytes()
	fmt.Println(buf.Bytes())
	fmt.Println("hello")
	return len, err
	// return len(b), nil
}

func main() {
	jsonFile := flag.String("creds", "", "User credentials token file")
	flag.Parse()

	file, err := ioutil.ReadFile(*jsonFile)
	if err != nil {
		panic(fmt.Sprintf("Failed to open the credentials file: %s\n", *jsonFile))
	}

	data := Credential{}

	_ = json.Unmarshal([]byte(file), &data)

	certChain := decodePem(data.Data.CA)
	for _, cert := range certChain.Certificate {
		x509Cert, err := x509.ParseCertificate(cert)
		if err != nil {
			panic(err)
		}

		if x509Cert.Subject.CommonName == "kube-apiserver-service-network-signer" {
			fmt.Println(x509Cert.Subject.CommonName)
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert,
			}

			// if b := pem.EncodeToMemory(block); b != nil {
			// 	data.Data.CA = b
			// }

			if err := pem.Encode(&data, block); err != nil {
				fmt.Println(err)
			}
			break
		}
	}
	// data.Data.CA = []byte("je;")
	mod_file, _ := json.MarshalIndent(data, "", " ")

	_ = ioutil.WriteFile(*jsonFile+"-mod.json", mod_file, 0644)

}

func decodePem(certPEMBlock []byte) tls.Certificate {
	var cert tls.Certificate
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	return cert
}
