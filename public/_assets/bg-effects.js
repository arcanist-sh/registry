// Background effects, demoscene style, drawn in WebGL behind parts of the page.
// Any <canvas data-fx="…"> gets one: "julia" (homepage hero) or "plasma" (site footer).
//   julia  — a Julia set whose parameter orbits the Mandelbrot edge, so the set keeps reshaping; smooth iteration
//            colouring feeds a slowly cycling teal / ice / mauve palette and only the filaments near the set glow.
//   plasma — fractal noise warped through itself three times ("silk plasma"): soft, liquid gradients, no hard edges.
// Subtle by construction: opacity and masks live in CSS, rendering runs below CSS resolution at ~30 fps, each canvas
// pauses off-screen and in background tabs, and prefers-reduced-motion gets a single still frame.
(function () {
  var canvases = document.querySelectorAll('canvas[data-fx]');
  if (!canvases.length) return;

  var HEAD = [
    'precision highp float;',
    'uniform vec2 res;uniform float t;uniform float light;',
    // Palette shared by every effect: hx teal, ice, BHC mauve; deeper variants on the light theme.
    'vec3 pal(float k,float k2){',
    '  vec3 teal=mix(vec3(.58,.89,.84),vec3(.09,.57,.60),light);',
    '  vec3 mauve=mix(vec3(.80,.65,.97),vec3(.53,.22,.94),light);',
    '  vec3 ice=mix(vec3(.54,.86,.92),vec3(.02,.55,.71),light);',
    '  return mix(mix(teal,ice,k2),mauve,smoothstep(.15,.85,k));',
    '}',
    'mat2 rot(float a){float c=cos(a),s=sin(a);return mat2(c,-s,s,c);}'
  ].join('\n');

  var FX = {
    julia: {
      scale: 0.6,
      fn: '',
      body: [
        'uv=rot(t*0.021)*uv;uv*=1.55+0.12*sin(t*0.05);',
        'float ph=t*0.035+0.9;vec2 c=0.7885*vec2(cos(ph),sin(ph));',
        'vec2 z=uv;float n=0.;float trap=1e3;',
        'for(int i=0;i<112;i++){z=vec2(z.x*z.x-z.y*z.y,2.*z.x*z.y)+c;trap=min(trap,abs(dot(z,z)-.35));if(dot(z,z)>256.)break;n+=1.;}',
        'if(n<112.){float mu=n+1.-log2(log(length(z)));float v=clamp(mu/112.,0.,1.);',
        ' al=pow(v,.55)*smoothstep(.02,.35,v);',
        // Palette cycling: bands drift slowly outward through the iteration count.
        ' col=pal(.5+.5*sin(mu*.21-t*.45+trap*2.5),.5+.5*sin(mu*.13-t*.3+1.7));}'
      ].join('\n')
    },
    plasma: {
      scale: 0.5,
      fn: [
        'float hash(vec2 p){return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453);}',
        'float noise(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);return mix(mix(hash(i),hash(i+vec2(1,0)),f.x),mix(hash(i+vec2(0,1)),hash(i+vec2(1,1)),f.x),f.y);}',
        'float fbm(vec2 p){float v=0.,a=.5;for(int i=0;i<6;i++){v+=a*noise(p);p=rot(.6)*p*2.02;a*=.5;}return v;}'
      ].join('\n'),
      body: [
        'vec2 p=uv*1.7;',
        'vec2 q=vec2(fbm(p+vec2(0.,t*.03)),fbm(p+vec2(5.2,1.3)-t*.025));',
        'vec2 r=vec2(fbm(p+3.*q+vec2(1.7,9.2)+t*.02),fbm(p+3.*q+vec2(8.3,2.8)));',
        'float f=fbm(p+3.*r);',
        'al=smoothstep(.35,.85,f)*.85+pow(length(q)*.6,3.)*.25;',
        'col=pal(clamp(length(r)*.9,0.,1.),clamp(q.x,0.,1.));'
      ].join('\n')
    }
  };

  function source(fx) {
    return HEAD + '\n' + fx.fn + '\nvoid main(){\n  vec2 uv=(gl_FragCoord.xy-0.5*res)/res.y;\n  vec3 col=vec3(0.);float al=0.;\n' +
      fx.body + '\n  al*=(0.9-0.25*light);gl_FragColor=vec4(col*al,al);\n}';
  }

  var root = document.documentElement;
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  var start = performance.now() - 40000; // start mid-orbit so the first frame is already an interesting shape
  var views = [];

  canvases.forEach(function (canvas) {
    var fx = FX[canvas.getAttribute('data-fx')];
    if (!fx) return;
    var gl = canvas.getContext('webgl', { alpha: true, premultipliedAlpha: true, antialias: false, powerPreference: 'low-power' });
    if (!gl) { canvas.remove(); return; }
    function shader(type, src) {
      var s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s);
      return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
    }
    var v = shader(gl.VERTEX_SHADER, 'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}');
    var f = shader(gl.FRAGMENT_SHADER, source(fx));
    if (!v || !f) { canvas.remove(); return; }
    var prog = gl.createProgram(); gl.attachShader(prog, v); gl.attachShader(prog, f); gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) { canvas.remove(); return; }
    gl.useProgram(prog);
    var buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    var loc = gl.getAttribLocation(prog, 'p'); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    views.push({ canvas: canvas, gl: gl, scale: fx.scale, visible: false,
      uRes: gl.getUniformLocation(prog, 'res'), uT: gl.getUniformLocation(prog, 't'), uLight: gl.getUniformLocation(prog, 'light') });
  });
  if (!views.length) return;

  function draw(view, now) {
    var c = view.canvas, gl = view.gl, r = c.getBoundingClientRect();
    var d = Math.min(window.devicePixelRatio || 1, 2) * view.scale;   // below CSS resolution: cheaper and softer
    var w = Math.max(1, Math.round(r.width * d)), h = Math.max(1, Math.round(r.height * d));
    if (c.width !== w || c.height !== h) { c.width = w; c.height = h; gl.viewport(0, 0, w, h); }
    gl.clearColor(0, 0, 0, 0); gl.clear(gl.COLOR_BUFFER_BIT);
    gl.uniform2f(view.uRes, w, h);
    gl.uniform1f(view.uT, (now - start) / 1000);
    gl.uniform1f(view.uLight, root.getAttribute('data-theme') === 'light' ? 1 : 0);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }
  function still() { views.forEach(function (v) { draw(v, start + 40000); }); }

  var raf = 0, last = 0;
  function anyVisible() { return views.some(function (v) { return v.visible; }); }
  function loop(now) {
    raf = 0;
    if (document.hidden || reduce.matches || !anyVisible()) return;
    if (now - last >= 33) { last = now; views.forEach(function (v) { if (v.visible) draw(v, now); }); }
    raf = requestAnimationFrame(loop);
  }
  function kick() {
    if (reduce.matches) { still(); return; }
    if (!raf && !document.hidden && anyVisible()) raf = requestAnimationFrame(loop);
  }

  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { views.forEach(function (v) { if (v.canvas === e.target) v.visible = e.isIntersecting; }); });
      kick();
    });
    views.forEach(function (v) { io.observe(v.canvas); });
  } else {
    views.forEach(function (v) { v.visible = true; });
  }
  still(); // paint once immediately so nothing pops in late
  document.addEventListener('visibilitychange', kick);
  reduce.addEventListener('change', kick);
  window.addEventListener('resize', function () { if (reduce.matches) still(); });
  // Re-colour immediately when the footer scheme switch flips the theme.
  new MutationObserver(function () { if (reduce.matches || !raf) still(); }).observe(root, { attributes: true, attributeFilter: ['data-theme'] });
  kick();
})();
