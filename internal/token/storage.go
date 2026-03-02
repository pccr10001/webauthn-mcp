package token

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type Storage struct {
	basePath string
	mu       sync.RWMutex
	cache    map[string]*Token
}

func NewStorage(basePath string) (*Storage, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, err
	}
	s := &Storage{
		basePath: basePath,
		cache:    make(map[string]*Token),
	}
	if err := s.loadAll(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Storage) tokenPath(id string) string {
	return filepath.Join(s.basePath, id+".json")
}

func (s *Storage) loadAll() error {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-5]
		token, err := s.loadToken(id)
		if err != nil {
			continue
		}
		s.cache[id] = token
	}
	return nil
}

func (s *Storage) loadToken(id string) (*Token, error) {
	data, err := os.ReadFile(s.tokenPath(id))
	if err != nil {
		return nil, err
	}
	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *Storage) Save(token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.tokenPath(token.ID), data, 0644); err != nil {
		return err
	}
	s.cache[token.ID] = token
	return nil
}

func (s *Storage) Get(id string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, ok := s.cache[id]
	if !ok {
		return nil, ErrTokenNotFound
	}
	return token, nil
}

func (s *Storage) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.cache[id]; !ok {
		return ErrTokenNotFound
	}
	if err := os.Remove(s.tokenPath(id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	delete(s.cache, id)
	return nil
}

func (s *Storage) List() []*Token {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tokens := make([]*Token, 0, len(s.cache))
	for _, token := range s.cache {
		tokens = append(tokens, token)
	}
	return tokens
}
