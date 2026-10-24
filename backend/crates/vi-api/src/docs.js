'use strict';
(async () => {
  const status = document.getElementById('status');
  try {
    const response = await fetch('/api-docs/openapi.json', { cache: 'no-store' });
    if (!response.ok) throw new Error('The API specification could not be loaded.');
    const spec = await response.json();
    const container = document.getElementById('endpoints');
    for (const [path, operations] of Object.entries(spec.paths || {})) {
      for (const [method, operation] of Object.entries(operations)) {
        if (!['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method)) continue;
        const details = document.createElement('details');
        const summary = document.createElement('summary');
        const label = document.createElement('b'); label.textContent = method.toUpperCase();
        const endpoint = document.createElement('code'); endpoint.textContent = path;
        summary.append(label, endpoint); details.append(summary);
        const description = document.createElement('p');
        description.textContent = operation.description || operation.summary || 'See the request and response schema below.';
        const schema = document.createElement('pre'); schema.textContent = JSON.stringify(operation, null, 2);
        details.append(description, schema);
        details.dataset.search = `${method} ${path} ${description.textContent}`.toLowerCase();
        container.append(details);
      }
    }
    document.getElementById('schemas').textContent = JSON.stringify(spec.components?.schemas || {}, null, 2);
    const filter = () => {
      const query = document.getElementById('search').value.toLowerCase(); let count = 0;
      for (const node of container.children) { node.hidden = !node.dataset.search.includes(query); if (!node.hidden) count++; }
      status.textContent = `${count} endpoints`;
    };
    document.getElementById('search').addEventListener('input', filter); filter();
  } catch (error) { status.textContent = error.message || 'Unable to load the API specification.'; }
})();
