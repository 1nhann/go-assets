package assets

import (
	"errors"
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"reflect"
)

type SessionPool struct {
	driver neo4j.Driver
	pool   chan neo4j.Session
}

func NewSessionPool(driver neo4j.Driver, size int) *SessionPool {
	pool := make(chan neo4j.Session, size)
	for i := 0; i < size; i++ {
		session := driver.NewSession(neo4j.SessionConfig{})
		pool <- session
	}
	return &SessionPool{
		driver: driver,
		pool:   pool,
	}
}
func (sp *SessionPool) GetSession() neo4j.Session {
	return <-sp.pool
}

func (sp *SessionPool) ReleaseSession(session neo4j.Session) {
	sp.pool <- session
}
func (sp *SessionPool) Close() {
	close(sp.pool)
	for session := range sp.pool {
		session.Close()
	}
}

// 资产结构体定义
type Target struct {
	Name string
	Info string
	//Domain string
	//IP     string
	//CIDR   string
}

type IP struct {
	IP   string
	Cidr string
}

type Port struct {
	Port int
	IP   string
}

type Domain struct {
	Domain string
}

type App struct {
	Name string
}
type MApp struct {
	Name string
}

type Fingerprint struct {
	Name string
	Rule string
}

type Vulnerability struct {
	ID   string
	Info string
	Poc  string
}

// AssetManager 管理资产数据的结构体
type AssetManager struct {
	Driver      neo4j.Driver
	SessionPool *SessionPool
}

func NewAssetManager(uri, username, password string) (*AssetManager, error) {
	driver, err := neo4j.NewDriver(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		return nil, fmt.Errorf("failed to create driver: %v", err)
	}
	return &AssetManager{
		Driver:      driver,
		SessionPool: NewSessionPool(driver, 10),
	}, nil
}

func (am *AssetManager) Close() {
	am.Driver.Close()
}

func (am *AssetManager) ClearDatabase() error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)

	clearQuery := `
        MATCH (n)
        DETACH DELETE n`
	_, err := session.Run(clearQuery, nil)
	if err != nil {
		return fmt.Errorf("failed to clear database: %v", err)
	}
	return nil
}
func (am *AssetManager) AddNode(node interface{}) error {
	switch n := node.(type) {
	case IP:
		return am.AddIP(n)
	case Port:
		return am.AddPort(n)
	case Domain:
		return am.AddDomain(n)
	case Fingerprint:
		return am.AddFingerprint(n)
	case Vulnerability:
		return am.AddVulnerability(n)
	case Target:
		return am.AddTarget(n)
	case App:
		return am.AddApp(n)
	case MApp:
		return am.AddMApp(n)
	}
	return nil
}

func (am *AssetManager) AddTarget(company Target) error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)

	createCompanyQuery := `
        MERGE (c:Target {name: $name})
        SET c.info = $info
        RETURN c`
	_, err := session.Run(createCompanyQuery, map[string]interface{}{
		"name": company.Name,
		"info": company.Info,
	})
	if err != nil {
		return fmt.Errorf("failed to create target node: %v", err)
	}
	return nil
}
func (am *AssetManager) AddApp(app App) error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)

	createCompanyQuery := `
        MERGE (c:App {name: $name})
        RETURN c`
	_, err := session.Run(createCompanyQuery, map[string]interface{}{
		"name": app.Name,
	})
	if err != nil {
		return fmt.Errorf("failed to create target node: %v", err)
	}
	return nil
}
func (am *AssetManager) AddMApp(app MApp) error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)

	createCompanyQuery := `
        MERGE (c:MApp {name: $name})
        RETURN c`
	_, err := session.Run(createCompanyQuery, map[string]interface{}{
		"name": app.Name,
	})
	if err != nil {
		return fmt.Errorf("failed to create target node: %v", err)
	}
	return nil
}
func (am *AssetManager) AddIP(ip IP) error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)

	createIpQuery := `
        MERGE (ip:IP {ip: $ip})
		SET ip.cidr = $cidr
        RETURN ip`
	_, err := session.Run(createIpQuery, map[string]interface{}{
		"ip":   ip.IP,
		"cidr": ip.Cidr,
	})
	if err != nil {
		return fmt.Errorf("failed to create IP node: %v", err)
	}
	return nil
}

func (am *AssetManager) AddPort(port Port) error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)
	createPortQuery := `
        MERGE (p:Port {port: $port, ip: $ip})
        RETURN p`
	_, err := session.Run(createPortQuery, map[string]interface{}{
		"port": port.Port,
		"ip":   port.IP,
	})
	if err != nil {
		return fmt.Errorf("failed to create port node: %v", err)
	}
	return nil
}

func (am *AssetManager) AddFingerprint(fingerprint Fingerprint) error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)

	createFingerprintQuery := `
        MERGE (f:Fingerprint {name: $fingerprint})
		SET f.rule = $rule
        RETURN f`
	_, err := session.Run(createFingerprintQuery, map[string]interface{}{"fingerprint": fingerprint.Name, "rule": fingerprint.Rule})
	if err != nil {
		return fmt.Errorf("failed to create fingerprint node: %v", err)
	}
	return nil
}

func (am *AssetManager) AddVulnerability(vulnerability Vulnerability) error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)

	createVulnerabilityQuery := `
        MERGE (v:Vulnerability {id: $vulnerability})
		SET v.info = $info
		SET v.poc = $poc
        RETURN v`
	_, err := session.Run(createVulnerabilityQuery, map[string]interface{}{"vulnerability": vulnerability.ID, "info": vulnerability.Info, "poc": vulnerability.Poc})
	if err != nil {
		return fmt.Errorf("failed to create vulnerability node: %v", err)
	}
	return nil
}

func (am *AssetManager) AddDomain(domain Domain) error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)

	createDomainQuery := `
        MERGE (d:Domain {domain: $name})
        RETURN d`
	_, err := session.Run(createDomainQuery, map[string]interface{}{"name": domain.Domain})
	if err != nil {
		return fmt.Errorf("failed to create domain node: %v", err)
	}
	return nil
}

func (am *AssetManager) AddRelation(node1 interface{}, node2 interface{}) error {
	session := am.SessionPool.GetSession()
	defer am.SessionPool.ReleaseSession(session)
	type1 := reflect.TypeOf(node1)
	type2 := reflect.TypeOf(node2)
	if type1 == reflect.TypeOf(Target{}) && type2 == reflect.TypeOf(IP{}) {
		createRelationshipsQuery := `
        MATCH (c:Target {name: $targetName}), (ip:IP {ip: $ip})
        MERGE (c)-[:HAS_IP]->(ip)
        RETURN c, ip`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"targetName": node1.(Target).Name,
			"ip":         node2.(IP).IP,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type2 == reflect.TypeOf(Target{}) && type1 == reflect.TypeOf(IP{}) {
		createRelationshipsQuery := `
        MATCH (c:Target {name: $targetName}), (ip:IP {ip: $ip})
        MERGE (c)-[:HAS_IP]->(ip)
        RETURN c, ip`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"targetName": node2.(Target).Name,
			"ip":         node1.(IP).IP,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}

	if type1 == reflect.TypeOf(Target{}) && type2 == reflect.TypeOf(Domain{}) {
		createRelationshipsQuery := `
        MATCH (c:Target {name: $targetName}), (domain:Domain {domain: $domain})
        MERGE (c)-[:HAS_DOMAIN]->(domain)
        RETURN c, domain`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"targetName": node1.(Target).Name,
			"domain":     node2.(Domain).Domain,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type2 == reflect.TypeOf(Target{}) && type1 == reflect.TypeOf(Domain{}) {
		createRelationshipsQuery := `
        MATCH (c:Target {name: $targetName}), (domain:Domain {domain: $domain})
        MERGE (c)-[:HAS_DOMAIN]->(domain)
        RETURN c, domain`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"targetName": node2.(Target).Name,
			"domain":     node1.(Domain).Domain,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}

	if type1 == reflect.TypeOf(Domain{}) && type2 == reflect.TypeOf(IP{}) {
		createRelationshipsQuery := `
        MATCH (d:Domain {domain: $domain}), (ip:IP {ip: $ip})
        MERGE (d)-[:RESOLVE_IP]->(ip)
        RETURN d, ip`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"domain": node1.(Domain).Domain,
			"ip":     node2.(IP).IP,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type2 == reflect.TypeOf(Domain{}) && type1 == reflect.TypeOf(IP{}) {
		createRelationshipsQuery := `
        MATCH (d:Domain {domain: $domain}), (ip:IP {ip: $ip}))
        MERGE (d)-[:RESOLVE_IP]->(ip)
        RETURN d, ip`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"domain": node2.(Domain).Domain,
			"ip":     node1.(IP).IP,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type1 == reflect.TypeOf(IP{}) && type2 == reflect.TypeOf(Port{}) {
		if node1.(IP).IP != node2.(Port).IP {
			return errors.New("invalid IP")
		}
		createRelationshipsQuery := `
        MATCH (port:Port {ip: $ip, port: $port}), (ip:IP {ip: $ip})
        MERGE (ip)-[:HAS_PORT]->(port)
        RETURN ip, port`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"ip":   node1.(IP).IP,
			"port": node2.(Port).Port,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type2 == reflect.TypeOf(IP{}) && type1 == reflect.TypeOf(Port{}) {
		if node1.(IP).IP != node2.(Port).IP {
			return errors.New("invalid IP")
		}
		createRelationshipsQuery := `
        MATCH (port:Port {ip: $ip, port: $port}), (ip:IP {ip: $ip})
        MERGE (ip)-[:HAS_PORT]->(port)
        RETURN ip, port`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"ip":   node2.(IP).IP,
			"port": node1.(Port).Port,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type1 == reflect.TypeOf(Port{}) && type2 == reflect.TypeOf(Fingerprint{}) {
		createRelationshipsQuery := `
        MATCH (port:Port {ip: $ip, port: $port}), (finger:Fingerprint {name: $finger})
        MERGE (port)-[:HAS_FINGER]->(finger)
        RETURN port, finger`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"ip":     node1.(Port).IP,
			"port":   node1.(Port).Port,
			"finger": node2.(Fingerprint).Name,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type2 == reflect.TypeOf(Port{}) && type1 == reflect.TypeOf(Fingerprint{}) {
		createRelationshipsQuery := `
        MATCH (port:Port {ip: $ip, port: $port}), (finger:Fingerprint {name: $finger})
        MERGE (port)-[:HAS_FINGER]->(finger)
        RETURN port, finger`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"ip":     node2.(Port).IP,
			"port":   node2.(Port).Port,
			"finger": node1.(Fingerprint).Name,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type1 == reflect.TypeOf(Port{}) && type2 == reflect.TypeOf(Vulnerability{}) {
		createRelationshipsQuery := `
        MATCH (port:Port {ip: $ip, port: $port}), (vuln:Vulnerability {id: $vuln})
        MERGE (port)-[:HAS_VULN]->(vuln)
        RETURN port, vuln`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"ip":   node1.(Port).IP,
			"port": node1.(Port).Port,
			"vuln": node2.(Vulnerability).ID,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type2 == reflect.TypeOf(Port{}) && type1 == reflect.TypeOf(Vulnerability{}) {
		createRelationshipsQuery := `
        MATCH (port:Port {ip: $ip, port: $port}), (vuln:Vulnerability {id: $vuln})
        MERGE (port)-[:HAS_VULN]->(vuln)
        RETURN port, vuln`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"ip":   node2.(Port).IP,
			"port": node2.(Port).Port,
			"vuln": node1.(Vulnerability).ID,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type1 == reflect.TypeOf(Fingerprint{}) && type2 == reflect.TypeOf(Vulnerability{}) {
		createRelationshipsQuery := `
        MATCH (finger:Fingerprint {name: $finger}), (vuln:Vulnerability {id: $vuln})
        MERGE (finger)-[:HAS_VULN]->(vuln)
        RETURN finger, vuln`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"finger": node1.(Fingerprint).Name,
			"vuln":   node2.(Vulnerability).ID,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type2 == reflect.TypeOf(Fingerprint{}) && type1 == reflect.TypeOf(Vulnerability{}) {
		createRelationshipsQuery := `
        MATCH (finger:Fingerprint {name: $finger}), (vuln:Vulnerability {id: $vuln})
        MERGE (finger)-[:HAS_VULN]->(vuln)
        RETURN finger, vuln`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"finger": node2.(Fingerprint).Name,
			"vuln":   node1.(Vulnerability).ID,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type1 == reflect.TypeOf(Target{}) && type2 == reflect.TypeOf(App{}) {
		createRelationshipsQuery := `
        MATCH (c:Target {name: $targetName}), (app:App {name: $name})
        MERGE (c)-[:HAS_APP]->(app)
        RETURN c,app`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"targetName": node1.(Target).Name,
			"name":       node2.(App).Name,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type2 == reflect.TypeOf(Target{}) && type1 == reflect.TypeOf(App{}) {
		createRelationshipsQuery := `
        MATCH (c:Target {name: $targetName}), (app:App {name: $name})
        MERGE (c)-[:HAS_APP]->(app)
        RETURN c,app`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"targetName": node2.(Target).Name,
			"name":       node1.(App).Name,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type1 == reflect.TypeOf(Target{}) && type2 == reflect.TypeOf(MApp{}) {
		createRelationshipsQuery := `
        MATCH (c:Target {name: $targetName}), (app:MApp {name: $name})
        MERGE (c)-[:HAS_MAPP]->(app)
        RETURN c,app`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"targetName": node1.(Target).Name,
			"name":       node2.(MApp).Name,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	if type2 == reflect.TypeOf(Target{}) && type1 == reflect.TypeOf(MApp{}) {
		createRelationshipsQuery := `
        MATCH (c:Target {name: $targetName}), (app:MApp {name: $name})
        MERGE (c)-[:HAS_MAPP]->(app)
        RETURN c,app`
		_, err := session.Run(createRelationshipsQuery, map[string]interface{}{
			"targetName": node2.(Target).Name,
			"name":       node1.(MApp).Name,
		})
		if err != nil {
			return fmt.Errorf("failed to create relationships: %v", err)
		}
	}
	return nil
}
