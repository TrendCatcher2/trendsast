package main
import ("database/sql"; "net/http"; "os/exec"; "os"; "crypto/tls"; "fmt")
func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  id := r.URL.Query().Get("id")
  db.Query("SELECT * FROM u WHERE id=" + id)
  exec.Command("sh", "-c", "ping "+id).Run()
  os.Open("/data/" + id)
  http.Get(r.FormValue("url"))
  http.Redirect(w, r, r.FormValue("next"), 302)
  fmt.Fprintf(w, "hi "+id)
  _ = &tls.Config{InsecureSkipVerify: true}
}
