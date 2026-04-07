package detectors

import (
	"math/rand"
	"sync"

	"github.com/go-faker/faker/v4"
)

// companySuffixes are common business entity suffixes used to generate
// realistic-looking fake company names.
var companySuffixes = []string{
	"Inc", "Corp", "LLC", "Ltd", "Group", "Solutions",
	"Technologies", "Systems", "Consulting", "Services",
	"Partners", "Associates", "Enterprises", "Holdings",
}

func randomCompanyName() string {
	suffix := companySuffixes[rand.Intn(len(companySuffixes))]
	return faker.LastName() + " " + suffix
}

func randomPersonName() string {
	return faker.FirstName() + " " + faker.LastName()
}

// ReplaceEnginePseudonymizer provides stable bidirectional mappings for
// replace_engine values: "company", "name", and "email".
type ReplaceEnginePseudonymizer struct {
	mu         sync.RWMutex
	realToFake map[string]string
	fakeToReal map[string]string
	engine     string
}

func NewReplaceEnginePseudonymizer(engine string) *ReplaceEnginePseudonymizer {
	return &ReplaceEnginePseudonymizer{
		realToFake: make(map[string]string),
		fakeToReal: make(map[string]string),
		engine:     engine,
	}
}

func (p *ReplaceEnginePseudonymizer) GetOrCreate(real string) string {
	p.mu.RLock()
	if fake, ok := p.realToFake[real]; ok {
		p.mu.RUnlock()
		return fake
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if fake, ok := p.realToFake[real]; ok {
		return fake
	}

	var fake string
	for {
		switch p.engine {
		case "company":
			fake = randomCompanyName()
		case "name":
			fake = randomPersonName()
		case "email":
			fake = faker.Email()
		default:
			fake = randomPersonName()
		}
		if _, exists := p.fakeToReal[fake]; !exists {
			break
		}
	}

	p.realToFake[real] = fake
	p.fakeToReal[fake] = real
	return fake
}

func (p *ReplaceEnginePseudonymizer) Restore(fake string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	real, ok := p.fakeToReal[fake]
	return real, ok
}
