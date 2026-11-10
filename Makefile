# DDI-Buntu — tâches courantes. « make help » les liste.
.PHONY: help console lint test-unit test-e2e test-shell single iso clean
help:
	@echo "make console    construit la console web (webui/.output) : Node 22 ou Docker"
	@echo "make lint       shellcheck et bash -n sur tous les scripts"
	@echo "make test-unit  typage + tests unitaires de la console (sans base)"
	@echo "make test-e2e   tests de bout en bout de la console (PostgreSQL : tools/setup-test-db.sh)"
	@echo "make test-shell batteries shell b01..b08 (Linux, root, voir docs/TESTING.md)"
	@echo "make single     fichier unique de publication : dist/build-ddibuntu.sh"
	@echo "make iso        construit l'ISO depuis le dépôt (Docker sous macOS/Windows)"
console:
	tools/build-console.sh
lint:
	shellcheck -x -s bash build-ddibuntu.sh tools/*.sh src/rootfs/usr/local/sbin/ddibuntu-* src/rootfs/usr/local/bin/ddibuntu-menu src/rootfs/usr/local/lib/ddibuntu/*.sh src/iso/late.sh src/iso/update.sh
	bash -n build-ddibuntu.sh
test-unit:
	tools/run-console-tests.sh unit
test-e2e:
	tools/run-console-tests.sh e2e
test-shell:
	sudo -E tests/run-all.sh
single: console
	tools/make-single.sh
iso: console
	./build-ddibuntu.sh
clean:
	rm -rf dist tests/artifacts tests/logs webui/.output webui/.nuxt
