package pathsafe

import (
	"net/http"
	"os"
	"path/filepath"
)

// DownloadInsecure serves GET /files/{name...}. ServeMux redirects requests
// whose raw path contains "..", which looks like protection, but wildcard
// values are unescaped: "/files/..%2F..%2Fetc%2Fpasswd" matches without a
// redirect and PathValue returns "../../etc/passwd".
func DownloadInsecure(base string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /files/{name...}", func(w http.ResponseWriter, r *http.Request) {
		b, err := ReadJoin(base, r.PathValue("name"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(b)
	})
	return mux
}

// Download serves the same route safely. filepath.Localize (Go 1.23) turns
// the slash-separated URL value into an OS path and rejects anything that is
// not a valid local io/fs path ("..", ".", empty or absolute elements, and
// on Windows backslashes and reserved names). The file is then opened
// through the os.Root, which also enforces the boundary against symlinks.
func Download(root *os.Root) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /files/{name...}", func(w http.ResponseWriter, r *http.Request) {
		name, err := filepath.Localize(r.PathValue("name"))
		if err != nil {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		b, err := root.ReadFile(name)
		if err != nil {
			// Missing files, escapes, symlink loops and permission errors
			// all end here; do not tell the client which one it was.
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(b)
	})
	return mux
}

// StaticInsecure is http.FileServer over http.Dir. The URL path is cleaned
// as if rooted at "/", so ".." cannot climb out lexically, but http.Dir
// follows symbolic links: a link inside the directory exposes whatever it
// points to.
func StaticInsecure(dir string) http.Handler {
	return http.FileServer(http.Dir(dir))
}

// Static serves the directory through os.Root.FS (Go 1.24) and
// http.FileServerFS (Go 1.22): the same file server, but every open goes
// through the root. os.DirFS would not help: it is documented to follow
// symlinks out of the tree just like os.Open.
func Static(root *os.Root) http.Handler {
	return http.FileServerFS(root.FS())
}
