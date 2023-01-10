package ss

type report struct {
	Deletes []string  `json:"deletes"`
	Updates []*listen `json:"updates"`
	Creates []*listen `json:"creates"`
}

func (r *report) doDelete(record string) {
	r.Deletes = append(r.Deletes, record)
}

func (r *report) doUpdate(ln *listen) {
	r.Updates = append(r.Updates, ln)
}

func (r *report) doCreate(ln *listen) {
	r.Creates = append(r.Creates, ln)
}

func (r *report) len() int {
	return len(r.Deletes) + len(r.Updates) + len(r.Creates)
}
