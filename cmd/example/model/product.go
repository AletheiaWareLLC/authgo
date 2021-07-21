package model

type Product struct {
	ID, Name string
}

type ProductManager interface {
	AddProduct(*Product)
	AllProducts() []*Product
	Product(string) *Product
}

type inMemoryProductManager struct {
	products map[string]*Product
}

func NewInMemoryProductManager() ProductManager {
	return &inMemoryProductManager{
		products: make(map[string]*Product),
	}
}

func (s *inMemoryProductManager) AddProduct(p *Product) {
	s.products[p.ID] = p
}

func (s *inMemoryProductManager) AllProducts() []*Product {
	var ps []*Product
	for _, p := range s.products {
		ps = append(ps, p)
	}
	return ps
}

func (s *inMemoryProductManager) Product(id string) *Product {
	return s.products[id]
}
