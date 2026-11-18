import { describe, expect, it } from 'vitest';

import { crossSiteScripting } from '../../src/rules/basic/xss.js';
import { memoryContext } from './helpers.js';

const at = (files: [string, string][]): string[] =>
  crossSiteScripting.run(memoryContext(files)).map((f) => `${f.filePath}:${f.lineStart}`);

describe('A37 ERB tag types: <%- and <% output nothing', () => {
  const DEVISE_LINKS = [
    "<%- if controller_name != 'sessions' %>",
    '  <%= link_to "Sign in", new_session_path(resource_name) %>',
    '<% end -%>',
    '',
    '<%- if devise_mapping.registerable? %>',
    '  <%= link_to "Sign up", new_registration_path(resource_name) %>',
    '<% end -%>',
    '',
    '<%- resource_class.omniauth_providers.each do |provider| %>',
    '  <%= link_to provider, omniauth_path(provider) %>',
    '<% end -%>',
  ].join('\n');

  it('MUST GO QUIET: ERB control-flow and trim tags render no characters', () => {
    expect(at([['app/views/devise/shared/_links.html.erb', DEVISE_LINKS]])).toEqual([]);
  });

  it('MUST STILL FIRE: <%= raw(user_value) %> is an explicit unescape', () => {
    expect(at([['app/views/posts/show.html.erb', '<div>\n  <%= raw(@post.body) %>\n</div>\n']]))
      .toEqual(['app/views/posts/show.html.erb:2']);
  });

  it('MUST STILL FIRE: raw without parentheses is the same decision', () => {
    expect(at([['app/views/posts/show.html.erb', '<%= raw @post.body %>\n']]))
      .toEqual(['app/views/posts/show.html.erb:1']);
  });

  it('MUST STILL FIRE: .html_safe on the value', () => {
    expect(at([['app/views/users/_user.html.erb', '<span>\n  <%= user.username.html_safe %>\n</span>\n']]))
      .toEqual(['app/views/users/_user.html.erb:2']);
  });

  it('MUST STILL FIRE: <%== %> is Erubi raw output', () => {
    expect(at([['app/views/posts/show.html.erb', '<%== @post.body %>\n']]))
      .toEqual(['app/views/posts/show.html.erb:1']);
  });

  it('MUST STILL FIRE: EJS keeps its own meaning for <%-', () => {
    expect(at([['views/post.ejs', '<div>\n<%- post.body %>\n</div>\n']]))
      .toEqual(['views/post.ejs:2']);
  });

  it('MUST GO QUIET: <%%= is the ESCAPE for a literal <%=, not a tag', () => {
    expect(at([['app/views/posts/show.html.erb', '<%%= f.input :name %>\n']])).toEqual([]);
  });

  it('MUST GO QUIET: a Rails generator template is codegen, not a view', () => {
    expect(at([['lib/templates/erb/scaffold/show.html.erb', '<%= raw(@record.body) %>\n']])).toEqual([]);
  });

  it('MUST STILL FIRE: the ordinary view the generator writes IS scanned', () => {
    expect(at([['app/views/records/show.html.erb', '<%= raw(@record.body) %>\n']]))
      .toEqual(['app/views/records/show.html.erb:1']);
  });
});

describe('A37 commented-out sinks are not sinks', () => {
  it('MUST GO QUIET: a commented-out innerHTML assignment', () => {
    const src = 'connect();\n// this.element.innerHTML = data.churp.view_count\n';
    expect(at([['app/javascript/controllers/view_churps_controller.js', src]])).toEqual([]);
  });

  it('MUST STILL FIRE: the live line below the commented one', () => {
    const src = '// this.element.innerHTML = data.old;\nthis.element.innerHTML = data.churp.body;\n';
    expect(at([['app/javascript/controllers/view_churps_controller.js', src]]))
      .toEqual(['app/javascript/controllers/view_churps_controller.js:2']);
  });

  it('MUST GO QUIET: a sink inside an HTML comment', () => {
    const src = '<div id="a"></div>\n<!-- <script>x.innerHTML = data.body;</script> -->\n';
    expect(at([['public/legacy.html', src]])).toEqual([]);
  });
});

describe('A37 dynamic is not user-influenced', () => {
  const IDEAS = [
    'const ideas = [',
    '  { id: 1, title: "Arhitectura", desc: "hint", price: 190 },',
    '  { id: 2, title: "Lumina", desc: "hint", price: 250 },',
    '];',
    'function renderIdeas() {',
    '  ideas.forEach(idea => {',
    '    card.innerHTML = `<h3>${idea.title}</h3><p>${idea.desc}</p><span>${idea.price}</span>`;',
    '  });',
    '}',
  ].join('\n');

  it('MUST GO QUIET: a hardcoded dictionary rendered into a card', () => {
    expect(at([['public/guru-store/app.js', IDEAS]])).toEqual([]);
  });

  it('MUST STILL FIRE: the same loop over a let that is pushed to elsewhere', () => {
    const src = [
      'let cart = [];',
      'function add(x) { cart.push(x); }',
      'function render() {',
      '  cart.forEach(item => {',
      '    el.innerHTML = `<span>${item.title}</span>`;',
      '  });',
      '}',
    ].join('\n');
    expect(at([['public/guru-store/app.js', src]])).toEqual(['public/guru-store/app.js:5']);
  });

  it('MUST STILL FIRE: element.innerHTML fed a request value', () => {
    const src = 'function render(req) {\n  const userInput = req.query.bio;\n  element.innerHTML = userInput;\n}\n';
    expect(at([['src/render.js', src]])).toEqual(['src/render.js:3']);
  });

  it('MUST STILL FIRE: dangerouslySetInnerHTML with data from the server', () => {
    const src = 'export function P({ data }) {\n  return <div dangerouslySetInnerHTML={{ __html: data.fromServer }} />;\n}\n';
    expect(at([['src/components/P.jsx', src]])).toEqual(['src/components/P.jsx:2']);
  });

  it('MUST STILL FIRE: a value from fetch, whose origin this file cannot settle', () => {
    const src = 'async function load() {\n  const data = await (await fetch("/api/x")).json();\n  el.innerHTML = data.message;\n}\n';
    expect(at([['src/load.js', src]])).toEqual(['src/load.js:3']);
  });

  it('MUST STILL FIRE: a constant mixed with anything unresolved', () => {
    const src = [
      'const PREFIX = "<b>";',
      'function render(props) {',
      '  el.innerHTML = `${PREFIX}${props.bio}`;',
      '}',
    ].join('\n');
    expect(at([['src/render.js', src]])).toEqual(['src/render.js:3']);
  });
});

describe('A37 development-only blocks do not ship', () => {
  it('MUST GO QUIET: a sink inside if (NODE_ENV !== "production")', () => {
    const src = "function debug(payload) {\n  if (process.env.NODE_ENV !== 'production') {\n    el.innerHTML = payload.body;\n  }\n}\n";
    expect(at([['src/debug.js', src]])).toEqual([]);
  });

  it('MUST STILL FIRE: the same sink outside the guard', () => {
    const src = "function debug(payload) {\n  if (process.env.NODE_ENV !== 'production') {\n    log();\n  }\n  el.innerHTML = payload.body;\n}\n";
    expect(at([['src/debug.js', src]])).toEqual(['src/debug.js:5']);
  });
});
