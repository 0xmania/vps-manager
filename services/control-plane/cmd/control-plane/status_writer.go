package main

import "net/http"

// Unwrap preserves optional interfaces such as http.Hijacker.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
