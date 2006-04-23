//
// PTLsim: Cycle Accurate x86-64 Simulator
// Statistical Analysis Tools
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>
#include <datastore.h>

char* mode_subtree;
char* mode_histogram;
char* mode_collect;
char* mode_collect_sum;
char* mode_collect_average;
char* mode_table;

char* table_row_names;
char* table_col_names;
char* table_row_col_pattern = "%r/%c.stats";
char* table_type_name = "text";
W64 table_use_percents = false;

char* graph_title;
double graph_width = 300.0;
double graph_height = 100.0;
double graph_clip_percentile = 95.0;
W64 graph_logscale = 0;
double graph_logk = 100.;

char* delta_start = null;
char* delta_end = "final";

W64 show_sum_of_subtrees_only = 0;

W64 maxdepth = limits<int>::max;

W64 table_scale_rel_to_col = limits<int>::max;
W64 table_mark_highest_col = 0;

W64 percent_digits = 1; // e.g. "66.7%"

double histogram_thresh = 0.0001;
W64 cumulative_histogram = 0;

W64 percent_of_toplevel = 0;

static ConfigurationOption optionlist[] = {
  {null,                                 OPTION_TYPE_SECTION, 0, "Mode", null},
  {"subtree",                            OPTION_TYPE_STRING,  0, "Subtree (specify path to node)", &mode_subtree},
  {"collect",                            OPTION_TYPE_STRING,  0, "Collect specific statistic from multiple data stores", &mode_collect},
  {"collectsum",                         OPTION_TYPE_STRING,  0, "Sum of same tree in all data stores", &mode_collect_sum},
  {"collectaverage",                     OPTION_TYPE_STRING,  0, "Average of same tree in all data stores", &mode_collect_average},
  {"histogram",                          OPTION_TYPE_STRING,  0, "Histogram of specific node (specify path to node)", &mode_histogram},
  {"table",                              OPTION_TYPE_STRING,  0, "Table of one node across multiple data stores", &mode_table},
  {null,                                 OPTION_TYPE_SECTION, 0, "Table", null},
  {"rows",                               OPTION_TYPE_STRING,  0, "Row names (comma separated)", &table_row_names},
  {"cols",                               OPTION_TYPE_STRING,  0, "Column names (comma separated)", &table_col_names},
  {"table-pattern",                      OPTION_TYPE_STRING,  0, "Pattern to convert row (%row) and column (%col) names into stats filename", &table_row_col_pattern},
  {"tabletype",                          OPTION_TYPE_STRING,  0, "Table type (text, latex, html)", &table_type_name},
  {"scale-relative-to-col",              OPTION_TYPE_W64,     0, "Scale all other table columns relative to specified column", &table_scale_rel_to_col},
  {"table-percents",                     OPTION_TYPE_BOOL,    0, "Show percents (as in tree) rather than absolute values", &table_use_percents},
  {"table-mark-highest-col",             OPTION_TYPE_BOOL,    0, "Mark highest column in each row", &table_mark_highest_col},
  {null,                                 OPTION_TYPE_SECTION, 0, "Statistics Range", null},
  {"deltastart",                         OPTION_TYPE_STRING,  0, "Snapshot to start at", &delta_start},
  {"deltaend",                           OPTION_TYPE_STRING,  0, "Snapshot to end at (i.e. subtract end - start)", &delta_end},
  {null,                                 OPTION_TYPE_SECTION, 0, "Display Control", null},
  {"sum-subtrees-only",                  OPTION_TYPE_BOOL,    0, "Show only the sum of subtrees in applicable nodes", &show_sum_of_subtrees_only},
  {"maxdepth",                           OPTION_TYPE_W64,     0, "Maximum tree depth", &maxdepth},
  {"percent-digits",                     OPTION_TYPE_W64,     0, "Precision of percentage listings in digits", &percent_digits},
  {"percent-of-toplevel",                OPTION_TYPE_BOOL,    0, "Show percent relative to toplevel node, not parent node", &percent_of_toplevel},
  {null,                                 OPTION_TYPE_SECTION, 0, "Histogram Options", null},
  {"title",                              OPTION_TYPE_STRING,  0, "Graph Title", &graph_title},
  {"width",                              OPTION_TYPE_FLOAT,   0, "Width in SVG pixels", &graph_width},
  {"height",                             OPTION_TYPE_FLOAT,   0, "Width in SVG pixels", &graph_height},
  {"percentile",                         OPTION_TYPE_FLOAT,   0, "Clip percentile", &graph_clip_percentile},
  {"logscale",                           OPTION_TYPE_BOOL,    0, "Use log scale", &graph_logscale},
  {"logk",                               OPTION_TYPE_FLOAT,   0, "Log scale constant", &graph_logk},
  {"cumulative-histogram",               OPTION_TYPE_BOOL,    0, "Cumulative histogram", &cumulative_histogram},
  {"histogram-thresh",                   OPTION_TYPE_FLOAT,   0, "Histogram threshold (1.0 = print nothing, 0.0 = everything)", &histogram_thresh},
};


const char* labels[] = {
  "L1hit", 
};

#define MAX_BENCHMARKS 256
#define MAX_SHORT_STATS_COUNT 256

stringbuf sbmatrix[MAX_BENCHMARKS][MAX_SHORT_STATS_COUNT];
double totals[MAX_SHORT_STATS_COUNT];

const char* benchnames[MAX_BENCHMARKS];

//
// NOTE: This is for example purposes only; modify as needed:
//
int ooo_get_short_stats(stringbuf* v, double* totals, DataStoreNode& root) {

  int n = 0;

  {
    {
      DataStoreNode& load = root("dcache")("load");
      DataStoreNode& hit = load("hit");

      W64 L1 = hit("L1");
      W64 L2 = hit("L2");
      W64 L3 = hit("L3");
      W64 mem = hit("mem");

      W64 total = (L1 + L2 + L3 + mem);

      double avgcycles = 
        (((double)L1 / (double)total) * 2.0) +
        (((double)L2 / (double)total) * 6.0) +
        (((double)L3 / (double)total) * (5.0 + 20.0)) +
        (((double)mem / (double)total) * (5.0 + 20.0 + 120.0));

      v[n] << floatstring(percent(L1, total), 4, 1);
      totals[n++] += percent(L1, total);

      v[n] << floatstring(percent(L2, total), 4, 1);
      totals[n++] += percent(L2, total);

      v[n] << floatstring(percent(L3, total), 4, 1);
      totals[n++] += percent(L3, total);

      v[n] << floatstring(percent(mem, total), 4, 1);
      totals[n++] += percent(mem, total);

      v[n] << floatstring(avgcycles, 4, 2);
      totals[n++] += avgcycles;
    }
  }

  return n;
}

void collect_short_stats(char** statfiles, int count) {
  assert(count < MAX_BENCHMARKS);

  int n = 0;

  foreach (i, count) {
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    cerr << "Collecting from ", statfiles[i], endl, flush;

    idstream is(statfiles[i]);
    assert(is);

    DataStoreNode& ds = *new DataStoreNode(is);
    n = ooo_get_short_stats(sbmatrix[i], totals, ds("final"));

    const char* p = strchr(statfiles[i], '/');
    benchnames[i] = (p) ? strndup(statfiles[i], p-statfiles[i]) : "Bench";

    delete &ds;
  }

  foreach (i, lengthof(totals)) {
    totals[i] /= (double)count;
  }
}

void print_short_stats_html(ostream& os, int count) {
  os << "<html>", endl;
  os << "<body>", endl;

  os << "<table cols=", count, " rows=", lengthof(labels), " border=1 cellpadding=3 cellspacing=0>";

  os << "<tr><td bgcolor='#c0c0c0'></td>";
  foreach (i, count) {
    os << "<td align=center bgcolor='#c0c0c0'><b>", benchnames[i], "</b></td>";
  }
  os << "</tr>", endl;

  foreach (j, lengthof(labels)) {
    os << "<tr>";
    os << "<td align=right bgcolor='#c0c0c0'><b>", labels[j], "</b></td>", endl;

    foreach (i, count) {
      os << "<td align=right>", sbmatrix[i][j], "</td>";
    }
    os << "</tr>", endl;
  }

  os << "</table>", endl;
  os << "</body>", endl;
  os << "</html>", endl;
}

void print_short_stats_latex(ostream& os, int count) {
  os << "\\documentclass[11pt]{article}", endl;
  os << "\\usepackage[latin1]{inputenc}\\usepackage{color}\\usepackage{graphicx}", endl;
  os << "\\providecommand{\\tabularnewline}{\\\\}", endl;
  os << "\\begin{document}", endl;
  os << "\\begin{tabular}{";
  foreach (i, count+2) { os << "|r"; }
  os << "|}", endl;
  os << "\\hline", endl;

  foreach (i, count) { 
    os << "&\\textsf{\\textbf{\\footnotesize{", benchnames[i], "}}}";
  }

  os << "&\\textsf{\\textbf{\\footnotesize{", "Avg", "}}}";

#if 0
  os << "\\tabularnewline\\hline\\hline", endl;
  os << "\\multicolumn{", count+1, "}{|c|}{\\textsf{\\textbf{\\footnotesize Baseline Processor (AMD Athlon 64 (K8), 2000 MHz)}}}\\tabularnewline\\hline\\hline", endl;

  os << "\\textsf{\\textbf{\\footnotesize{Cycles}}}";
  foreach (i, count) {
    os << "&\\textsf{\\footnotesize{", 0, "}}";
  }

  os << "\\tabularnewline\\hline", endl;

  os << "\\textsf{\\textbf{\\footnotesize{Speedup}}}";
  foreach (i, count) {
    os << "&\\textsf{\\footnotesize{", 0, "}}";
  }

#endif

  os << "\\tabularnewline\\hline\\hline", endl;
  os << "\\multicolumn{", count+2, "}{|c|}{\\textsf{\\textbf{\\footnotesize Experimental Model}}}\\tabularnewline\\hline\\hline", endl;

  foreach (j, lengthof(labels)) {
    os << "\\textsf{\\textbf{\\footnotesize{", labels[j], "}}}";
    foreach (i, count) {
      os << "&\\textsf{\\footnotesize{", sbmatrix[i][j], "}}";
    }
    os << "&\\textsf{\\footnotesize{", floatstring(totals[j], 0, 1), "}}";
    os << "\\tabularnewline\\hline", endl;
  }
  os << "\\end{tabular}", endl;
  os << "\\end{document}", endl;
}

struct RGBAColor {
  float r;
  float g;
  float b;
  float a;
};

struct RGBA: public RGBAColor {
  RGBA() { }

  RGBA(float r, float g, float b, float a = 255) {
    this->r = r;
    this->g = g;
    this->b = b;
    this->a = a;
  }

  RGBA(const RGBAColor& rgba) {
    r = rgba.r;
    g = rgba.g;
    b = rgba.b;
    a = rgba.a;
  }
};

ostream& operator <<(ostream& os, const RGBA& rgba) {
  os << '#', hexstring((byte)math::round(rgba.r), 8), hexstring((byte)math::round(rgba.g), 8), hexstring((byte)math::round(rgba.b), 8);
  return os;
}

class SVGCreator {
public:
  ostream* os;
  int idcounter;

  bool filled;
  RGBA fill;
  RGBA stroke;
  float strokewidth;
  char* fontinfo;
  float xoffs;
  float yoffs;

  float dashoffset;
  float dashon;
  float dashoff;

  SVGCreator(ostream& os, float width, float height) {
    this->os = &os;
    idcounter = 0;
    filled = 1;
    fill = RGBA(0, 0, 0, 255);
    stroke = RGBA(0, 0, 0, 255);
    strokewidth = 0.1;
    fontinfo = null;
    setoffset(0, 0);
    setdash(0, 0, 0);
    setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:middle;writing-mode:lr-tb");

    printheader(width, height);
  }

  void setdash(float dashoffset, float dashon = 0, float dashoff = 0) {
    this->dashoffset = dashoffset;
    this->dashon = dashon;
    this->dashoff = dashoff;
  }

  void setoffset(float x, float y) {
    xoffs = x; yoffs = y;
  }

  void setfont(const char* font) {
    if (fontinfo) free(fontinfo);
    fontinfo = strdup(font);
  }

  ostream& printstyle(ostream& os) {
    os << "fill:"; if (filled) os << fill; else os << "none"; os << ";";
    os << "fill-opacity:", (fill.a / 255.0), ";";
    if (filled) os << "fill-rule:evenodd;";
    os << "stroke:"; if (strokewidth > 0) os << stroke; else os << "none"; os << ";";
    os << "stroke-width:", strokewidth, ";";
    os << "stroke-linecap:round;stroke-linejoin:miter;stroke-miterlimit:4.0;";
    os << "stroke-opacity:", (stroke.a / 255.0), ";";
    if (dashon) os << "stroke-dashoffset:", dashoffset, ";stroke-dasharray:", dashon, ",", dashoff, endl;
    return os;
  }

  ostream& printfont(ostream& os) {
    os << fontinfo, ';';
    return os;
  }

  void printheader(float width, float height) {
    *os << "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>", endl;
    *os << "<svg xmlns:svg=\"http://www.w3.org/2000/svg\" xmlns=\"http://www.w3.org/2000/svg\" id=\"svg2\" height=\"", height, "\" width=\"", width, "\" y=\"0.0\" x=\"0.0000000\" version=\"1.0\">", endl;
  }

  void newlayer(const char* name = null) {
    if (!name)
      *os << "<g id=\"", "layer", idcounter++, "\">", endl;
    else *os << "<g id=\"", name, "\">", endl;
  }

  void exitlayer() {
    *os << "</g>", endl;
  }

  void rectangle(float x, float y, float width, float height) {
    *os << "<rect id=\"rect", idcounter++, "\" style=\"";
    printstyle(*os);
    *os << "\" y=\"", (y + yoffs), "\" x=\"", (x + xoffs), "\" height=\"", height, "\" width=\"", width, "\" />", endl;
  }

  void text(const char* string, float x, float y) {
    *os << "<text xml:space=\"preserve\" id=\"text", idcounter++, "\" style=\"";
    printstyle(*os);
    printfont(*os);
    *os << "\" y=\"", y, "\" x=\"", x, "\">", endl;
    *os << "<tspan id=\"tspan", idcounter++, "\" y=\"", (y + yoffs), "\" x=\"", (x + xoffs), "\">", string, "</tspan></text>", endl;
  }

  void line(float x1, float y1, float x2, float y2) {
    *os << "<path id=\"path", idcounter++, "\" style=\"";
    printstyle(*os);
    *os << "\" d=\"M ", (x1 + xoffs), ",", (y1 + yoffs), " L ", (x2 + xoffs), ",", (y2 + yoffs), "\" />", endl;
  }

  void startpath(float x, float y) {
    *os << "<path id=\"path", idcounter++, "\" style=\"";
    printstyle(*os);
    *os << "\" d=\"M ", (x + xoffs), ",", (y + yoffs);
  }

  void nextpoint(float x, float y) {
    *os << " L ", (x + xoffs), ",", (y + yoffs);
  }

  void endpath() {
    *os << "\" />", endl;
  }

  void finalize() {
    *os << "</svg>", endl;
  }

  ~SVGCreator() {
    finalize();
  }
};

static inline double logscale(double x) {
  return log(1 + (x*graph_logk)) / log(1 + graph_logk);
}

static inline double invlogscale(double x) {
  return (exp(x*log(1 + graph_logk)) - 1) / graph_logk;
}

const RGBA graph_background(225, 207, 255);

void create_svg_of_histogram_percent_bargraph(ostream& os, W64s* histogram, int count, const char* title = null, double imagewidth = 300.0, double imageheight = 100.0) {
  double leftpad = 10.0;
  double toppad = 5.0;
  double rightpad = 4.0;
  double bottompad = 5.0;

  if (title) toppad += 16;

  int maxwidth = 0;

  W64 total = 0;
  foreach (i, count) { total += histogram[i]; }

  double cum = 0;
  foreach (i, count) { 
    cum += ((double)histogram[i] / (double)total);
    maxwidth++;
    if (cum >= (graph_clip_percentile / 100.0)) break;
  }

  double maxheight = 0;
  foreach (i, maxwidth+1) { maxheight = max(maxheight, (double)histogram[i] / (double)total); }

  double xscale = imagewidth / ((double)maxwidth + 1);

  SVGCreator svg(os, imagewidth + leftpad + rightpad, imageheight + toppad + bottompad);

  svg.newlayer();

  svg.strokewidth = 0.0;
  svg.stroke = RGBA(255, 255, 255);
  svg.filled = 0;
  svg.rectangle(0, 0, imagewidth + leftpad + rightpad, imageheight + toppad + bottompad);

  svg.setoffset(leftpad, toppad);

  if (title) {
    svg.fill = RGBA(0, 0, 0);
    svg.filled = 1;
    svg.setfont("font-size:8;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:middle;writing-mode:lr-tb");
    svg.text(title, imagewidth / 2, -6);
  }

  svg.stroke = RGBA(0, 0, 0);
  svg.strokewidth = 0.0;
  svg.filled = 1;
  svg.fill = graph_background;
  svg.rectangle(0, 0, (maxwidth+1) * xscale, imageheight);

  svg.strokewidth = 0.0;

  svg.fill = RGBA(64, 0, 255);

  foreach (i, maxwidth+1) {
    double x = ((double)histogram[i] / (double)total) / maxheight;
    if (graph_logscale) x = logscale(x);
    double barsize = x * imageheight;

    if (barsize >= 0.1) svg.rectangle(i*xscale, imageheight - barsize, xscale, barsize);
  }

  svg.fill = RGBA(0, 0, 0);

  svg.setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:middle;writing-mode:lr-tb");

  for (double i = 0; i <= 1.0; i += 0.1) {
    stringbuf sb;
    sb << floatstring(i * maxwidth, 0, 0);
    svg.text(sb, i * imagewidth, imageheight + 3.0);
  }

  svg.setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:end;writing-mode:lr-tb");

  for (double i = 0; i <= 1.0; i += 0.2) {
    stringbuf sb;
    double value = (graph_logscale) ? (invlogscale(i) * maxheight * 100.0) : (i * maxheight * 100.0);
    double y = ((1.0 - i)*imageheight);
    sb << floatstring(value, 0, 0), "%";
    svg.text(sb, -0.2, y - 0.2);

    svg.strokewidth = 0.1;
    svg.stroke = RGBA(170, 156, 192);
    svg.line(-6, y, (maxwidth+1) * xscale, y);
    svg.strokewidth = 0;
  }

  for (double x = 0; x <= 1.0; x += 0.05) {
    svg.strokewidth = 0.1;
    svg.stroke = RGBA(170, 156, 192);
    svg.line(x * imagewidth, 0, x * imagewidth, imageheight);
    svg.strokewidth = 0;
  }

  svg.exitlayer();
}

struct TimeLapseFieldsBase {
  W64 start;
  W64 length;
  double values[];
};

//
// NOTE: this is for example purposes only; add additional fields as needed
//
struct TimeLapseFields: public TimeLapseFieldsBase {
  double cache_hit_rate;                          // L1 cache hit rate in percent
};

static const int fieldcount = (sizeof(TimeLapseFields) - sizeof(TimeLapseFieldsBase)) / sizeof(double);

struct LineAttributes {
  bool enabled;
  bool stacked;
  RGBAColor stroke;
  float width;
  float dashoffset;
  float dashon;
  float dashoff;
  bool filled;
  RGBAColor fill;
};

void create_svg_of_percentage_line_graph(ostream& os, double* xpoints, int xcount, double** ypoints, int ycount, 
                                         double imagewidth, double imageheight, const LineAttributes* linetype, const RGBA& background) {
  double leftpad = 10.0;
  double toppad = 5.0;
  double rightpad = 4.0;
  double bottompad = 5.0;

  double xmax = 0;

  foreach (i, xcount) {
    xmax = max(xmax, xpoints[i]);
  }

  double xscale = imagewidth / xmax;

  double yscale = imageheight / 100.0;

  SVGCreator svg(os, imagewidth + leftpad + rightpad, imageheight + toppad + bottompad);
  svg.setoffset(leftpad, toppad);

  svg.newlayer();

  svg.stroke = RGBA(0, 0, 0);
  svg.strokewidth = 0.1;
  svg.filled = 1;
  svg.fill = background;
  svg.rectangle(0, 0, imagewidth, imageheight);

  svg.strokewidth = 0.1;
  svg.stroke = RGBA(0, 0, 0);
  svg.strokewidth = 0.1;
  svg.filled = 0;
  svg.fill = RGBA(0, 0, 0);

  double* stackbase = new double[xcount];
  foreach (i, xcount) stackbase[i] = 0;

  foreach (j, ycount) {
    const LineAttributes& line = linetype[j];

    if (!line.enabled)
      continue;
    if (!line.stacked)
      continue;
  
    foreach (i, xcount) {
      ypoints[j][i] += stackbase[i];
      stackbase[i] = ypoints[j][i];
    }
  }

  delete[] stackbase;

  for (int layer = 1; layer >= 0; layer--) {
    for (int j = ycount-1; j >= 0; j--) {
      const LineAttributes& line = linetype[j];
      svg.strokewidth = line.width;
      svg.stroke = line.stroke;
      svg.setdash(line.dashoffset, line.dashon, line.dashoff);
      svg.filled = line.filled;
      svg.fill = line.fill;

      if (!line.enabled)
        continue;

      if (line.stacked != layer)
        continue;

      foreach (i, xcount) {
        double yy = ypoints[j][i];
        double x = xpoints[i] * xscale;
        double y = imageheight - (yy * yscale);
        if (i == 0) x = 0; else if (i == xcount-1) x = imagewidth;
        y = clipto(y, 0.0, imageheight);
        if (i == 0) { if (line.filled) svg.startpath(0, imageheight); else svg.startpath(x, y); }
        svg.nextpoint(x, y);
      }

      if (line.filled) svg.nextpoint(imagewidth, imageheight);
      svg.endpath();
    }
  }

  svg.filled = 1;
  svg.fill = RGBA(0, 0, 0);
  svg.strokewidth = 0;
  svg.setdash(0);

  svg.setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:middle;writing-mode:lr-tb");

  for (double i = 0; i <= 1.0; i += 0.1) {
    stringbuf sb;
    sb << floatstring(i * xmax, 0, 0);
    svg.text(sb, i * imagewidth, imageheight + 4.0);
  }

  svg.setfont("font-size:4;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-family:Arial;text-anchor:end;writing-mode:lr-tb");

  for (double i = 0; i <= 1.0; i += 0.1) {
    stringbuf sb;
    double value = i * 100.0;

    double y = ((1.0 - i)*imageheight);

    sb << floatstring(value, 0, 0), "%";
    svg.text(sb, -0.3, y - 0.3);

    svg.strokewidth = 0.1;
    svg.stroke = RGBA(170, 156, 192);
    svg.line(-6, y, imagewidth, y);
    svg.strokewidth = 0;
  }

  for (double x = 0; x <= 1.0; x += 0.05) {
    svg.strokewidth = 0.1;
    svg.stroke = RGBA(170, 156, 192);
    svg.line(x * imagewidth, 0, x * imagewidth, imageheight);
    svg.strokewidth = 0;
  }

  svg.exitlayer();
}

void create_time_lapse_graph(ostream& os, DataStoreNode& root, const LineAttributes* linetype = null, const RGBA& background = RGBA(225, 207, 255), bool print_table_not_svg = false) {
  dynarray<TimeLapseFields> timelapse;

  int snapshotid = 1;
  for (;;) {
    stringbuf sb;

    sb.reset();
    sb << snapshotid-1;
    DataStoreNode& prev = root(sb);
  
    sb.reset();
    sb << snapshotid;

    DataStoreNode* nodeptr = root.search(sb);
    if (!nodeptr)
      break;

    DataStoreNode& node = root(sb);

    DataStoreNode& diff = *(node - prev);

    TimeLapseFields fields;

    int n = 0;

    fields.start = prev("ptlsim")("cycles");
    fields.length = diff("ptlsim")("cycles");


    {
      DataStoreNode& dcache = diff("dcache");

      {
        DataStoreNode& load = dcache("load");
        DataStoreNode& hit = load("hit");

        W64 L1 = hit("L1");
        W64 L2 = hit("L2");
        W64 L3 = hit("L3");
        W64 mem = hit("mem");
        W64 total = (L1 + L2 + L3 + mem);

        fields.cache_hit_rate = percent(L1, total);
      }
    }

    timelapse.push(fields);

    snapshotid++;

    delete &diff;
  }

  int n = timelapse.length;

  if (print_table_not_svg) {
    os << "Printing ", fieldcount, " fields:", endl;
    foreach (i, n) {
      const TimeLapseFieldsBase& fields = timelapse[i];
      os << "  ", intstring(i, 4), " @ ", intstring((W64)math::round((double)fields.start / 1000000.), 10), "M:";
      
      foreach (j, fieldcount) {
        os << " ", floatstring(fields.values[j], 5, 1);
      }
      os << endl;
    }
    return;
  }

  double* xpoints = new double[timelapse.length];
  double** ypoints = new double*[fieldcount];

  foreach (j, fieldcount) {
    ypoints[j] = new double[timelapse.length];
    foreach (i, timelapse.length) {
      const TimeLapseFieldsBase& snapshot = timelapse[i];
      xpoints[i] = math::round((double)(snapshot.start + snapshot.length) / 1000000.);
      ypoints[j][i] = snapshot.values[j];
    }
  }

  create_svg_of_percentage_line_graph(os, xpoints, timelapse.length, ypoints, fieldcount, 100.0, 50.0, linetype, background);

  foreach (j, fieldcount) {
    delete[] ypoints[j];
  }

  delete[] xpoints;
}

#define NOLINE {0, 0, {0, 0, 0, 0}, 0.00, 0.00, 0.00, 0.00, 0, {0, 0, 0, 0}}

static const LineAttributes linetype_allfields[fieldcount] = {
  {1, 0, {0,   255, 255, 255}, 0.10, 0.00, 0.00, 0.00, 0, {0,   0,   0,   0  }}, // L1 cache hit rate in percent
};


void printbanner() {
  cerr << "//  ", endl;
  cerr << "//  PTLstats: PTLsim statistics data store analysis tool", endl;
  cerr << "//  Copyright 1999-2005 Matt T. Yourst <yourst@yourst.com>", endl;
  cerr << "//  ", endl;
  cerr << endl;
}

DataStoreNode* collect_into_supernode(int argc, char** argv, char* path) {
  DataStoreNode* supernode = new DataStoreNode("super");

  foreach (i, argc) {
    char* filename = argv[i];
        
    idstream is(filename);
    if (!is) {
      cerr << "ptlstats: Cannot open '", filename, "'", endl, endl;
      return null;
    }
        
    DataStoreNode* ds = new DataStoreNode(is);
    ds = ds->searchpath(path);
        
    if (!ds) {
      cerr << "ptlstats: Error: cannot find subtree '", path, "'", endl;
      return null;
    }

    // Can't have slashes in tree pathnames
    int filenamelen = strlen(filename);
    foreach (i, filenamelen) { if (filename[i] == '/') filename[i] = ':'; }

    ds->rename(filename);

    supernode->add(ds);
  }

  return supernode;
}

class TableCreator {
public:
  ostream& os;
  dynarray<char*>& rownames;
  dynarray<char*>& colnames;
  int row_name_width;
public:
  TableCreator(ostream& os_, dynarray<char*>& rownames_, dynarray<char*>& colnames_):
    os(os_), rownames(rownames_), colnames(colnames_) {
    row_name_width = 0;
    foreach (i, rownames.size()) row_name_width = max(row_name_width, (int)strlen(rownames[i]));
  }

  virtual void start_header_row() {
    os << padstring("", row_name_width);
  }

  virtual void print_header(int col) {
    os << "  ", padstring(colnames[col], 8);
  }

  virtual void end_header_row() {
    os << endl;
  }

  virtual void start_row(int row) {
    os << padstring(rownames[row], row_name_width);
  }

  virtual void print_data(double value, int row, int column) {
    bool isint = ((value - math::floor(value)) < 0.0000001);
    int width = max((int)strlen(colnames[column]), 8) + 2;
    if (isint) os << intstring((W64s)value, width); else os << floatstring(value, width, 3);
  }

  virtual void end_row() {
    os << endl;
  }

  virtual void start_special_row(const char* title) {
    os << padstring(title, row_name_width);
  }

  virtual void end_table() { }
};

class LaTeXTableCreator: public TableCreator {
public:
  LaTeXTableCreator(ostream& os_, dynarray<char*>& rownames_, dynarray<char*>& colnames_):
    TableCreator(os_, rownames_, colnames_) {
    os << "\\documentclass{article}", endl;
    os << "\\makeatletter", endl;
    os << "\\providecommand{\\tabularnewline}{\\\\}", endl;
    os << "\\makeatother", endl;
    os << "\\begin{document}", endl;

    os << "\\begin{tabular}{|c|";
    foreach (i, colnames.size()) { os << "|c"; }
    os << "|}", endl;
    os << "\\hline", endl;
  }

  virtual void start_header_row() { }

  virtual void print_header(int col) {
    os << "&", colnames[col];
  }

  virtual void end_header_row() {
    os << "\\tabularnewline\\hline\\hline", endl;
  }

  virtual void start_row(int row) {
    os << rownames[row];
  }

  virtual void start_special_row(const char* title) {
    os << title;
  }

  virtual void print_data(double value, int row, int column) {
    os << "&";
    bool isint = ((value - math::floor(value)) < 0.0000001);
    if (isint) os << (W64s)value; else os << floatstring(value, 0, 1);
  }

  virtual void end_row() {
    os << "\\tabularnewline\\hline", endl;
  }

  virtual void end_table() {
    os << "\\end{tabular}", endl;
    os << "\\end{document}", endl;
  }
};

enum { TABLE_TYPE_TEXT, TABLE_TYPE_LATEX, TABLE_TYPE_HTML };

void create_table(ostream& os, int tabletype, const char* statname, const char* rownames, const char* colnames, const char* row_col_pattern, int scale_relative_to_col) {
  dynarray<char*> rowlist;
  rowlist.tokenize(rownames, ",");
  dynarray<char*> collist;
  collist.tokenize(colnames, ",");

  TableCreator* creator;
  switch (tabletype) {
  case TABLE_TYPE_TEXT:
    creator = new TableCreator(os, rowlist, collist); break;
  case TABLE_TYPE_LATEX:
    creator = new LaTeXTableCreator(os, rowlist, collist); break;
  case TABLE_TYPE_HTML:
    assert(false);
  }

  dynarray<double> sum_of_all_rows;
  sum_of_all_rows.resize(collist.size());
  sum_of_all_rows.fill(0);

  dynarray< dynarray<double> > data;
  data.resize(rowlist.size());

  //
  // Collect data
  //
  const char* findarray[2] = {"%row", "%col"};

  for (int row = 0; row < rowlist.size(); row++) {
    data[row].resize(collist.size());
    for (int col = 0; col < collist.size(); col++) {
      stringbuf filename;

      const char* replarray[2];
      replarray[0] = rowlist[row];
      replarray[1] = collist[col];
      stringsubst(filename, table_row_col_pattern, findarray, replarray, 2);

      idstream is(filename);
      if (!is) {
        cerr << "ptlstats: Cannot open '", filename, "' for row ", row, ", col ", col, endl, endl;
        return;
      }
        
      DataStoreNode* ds = new DataStoreNode(is);
      assert(ds);
      ds = ds->searchpath(statname);

      double value;
      if (ds) {
        value = *ds;
        sum_of_all_rows[col] += value;
      } else { 
        cerr << "ptlstats: Warning: cannot find subtree '", statname, "' for row ", row, ", col ", col, endl;
        value = 0;
      }

      data[row][col] = value;
    }
  }

  //
  // Print data
  //
  creator->start_header_row();
  for (int col = 0; col < collist.size(); col++) creator->print_header(col);
  creator->end_header_row();

  for (int row = 0; row < rowlist.size(); row++) {
    double relative_base = 0;
    creator->start_row(row);
    for (int col = 0; col < collist.size(); col++) {
      double value = data[row][col];

      if (scale_relative_to_col < collist.size()) {
        if (col != scale_relative_to_col) {
          value = ((data[row][scale_relative_to_col] / value) - 1.0) * 100.0;
        }
      }

      creator->print_data(value, row, col);
    }
    creator->end_row();
  }

  {
    double relative_base = 0;
    creator->start_special_row("Total");
    for (int col = 0; col < collist.size(); col++) {
      double value = sum_of_all_rows[col];

      if (scale_relative_to_col < collist.size()) {
        if (col == scale_relative_to_col) {
          relative_base = value;
        } else {
          value = ((relative_base / value) - 1.0) * 100.0;
        }
      }

      creator->print_data(value, rowlist.size()+0, col);
    }
    creator->end_row();
  }

  creator->end_table();
}

int main(int argc, char* argv[]) {

  ConfigurationParser options(optionlist, lengthof(optionlist));

  argc--; argv++;

  if (!argc) {
    printbanner();
    cerr << "Syntax is:", endl;
    cerr << "  ptlstats [-options] statsfile", endl, endl;
    options.printusage(cerr);
    return 1;
  }

  int n = options.parse(argc, argv);

  bool no_args_needed = mode_table;

  if ((n < 0) & (!no_args_needed)) {
    printbanner();
    cerr << "ptlstats: Error: no statistics data store filename given", endl, endl;
    cerr << "Syntax is:", endl;
    cerr << "  ptlstats [-options] statsfile", endl, endl;
    options.printusage(cerr);
    return 1;
  }

  char* filename = (no_args_needed) ? null : argv[n];

  DataStoreNodePrintSettings printinfo;
  printinfo.force_sum_of_subtrees_only = show_sum_of_subtrees_only;
  printinfo.maxdepth = maxdepth;
  printinfo.percent_digits = percent_digits;
  printinfo.percent_of_toplevel = percent_of_toplevel;
  printinfo.histogram_thresh = histogram_thresh;
  printinfo.cumulative_histogram = cumulative_histogram;

  if (mode_histogram) {
    idstream is(filename);
    if (!is) {
      cerr << "ptlstats: Cannot open '", filename, "'", endl, endl;
      return 2;
    }

    DataStoreNode* ds = new DataStoreNode(is);

    ds = ds->searchpath(mode_histogram);
    
    if (!ds) {
      cerr << "ptlstats: Error: cannot find subtree '", mode_histogram, "'", endl;
      return 1;
    }

    if (!ds->histogramarray) {
      cerr << "ptlstats: Error: subtree '", mode_histogram, "' is not a histogram array node", endl;
      return 1;
    }
    create_svg_of_histogram_percent_bargraph(cout, *ds, ds->count, graph_title, graph_width, graph_height);
    delete ds;
  } else if (mode_collect) {
    argv += n; argc -= n;

    DataStoreNode* supernode = collect_into_supernode(argc, argv, mode_collect);
    if (!supernode) return -1;
    supernode->identical_subtrees = 0;
    supernode->print(cout, printinfo);
    delete supernode;
  } else if (mode_collect_sum) {
    argv += n; argc -= n;
    DataStoreNode* supernode = collect_into_supernode(argc, argv, mode_collect_sum);
    if (!supernode) return -1;
    supernode->identical_subtrees = 1;
    DataStoreNode* sumnode = supernode->sum_of_subtrees();
    sumnode->rename(mode_collect_sum);
    sumnode->print(cout, printinfo);
    delete supernode;
  } else if (mode_collect_average) {
    argv += n; argc -= n;
    DataStoreNode* supernode = collect_into_supernode(argc, argv, mode_collect_average);
    if (!supernode) return -1;
    supernode->identical_subtrees = 1;
    DataStoreNode* avgnode = supernode->average_of_subtrees();
    avgnode->summable = 1;
    avgnode->rename(mode_collect_average);
    avgnode->print(cout, printinfo);
    delete supernode;
  } else if (delta_start) {
    idstream is(filename);
    if (!is) {
      cerr << "ptlstats: Cannot open '", filename, "'", endl, endl;
      return 2;
    }

    DataStoreNode* ds = new DataStoreNode(is);

    DataStoreNode* startds = ds->searchpath(delta_start);

    if (!startds) {
      cerr << "ptlstats: Error: cannot find starting snapshot '", delta_start, "'", endl;
      return 1;
    }

    DataStoreNode* endds = ds->searchpath(delta_end);

    if (!endds) {
      cerr << "ptlstats: Error: cannot find ending snapshot '", delta_end, "'", endl;
      return 1;
    }

    DataStoreNode* deltads = *endds - *startds;

    deltads->print(cout, printinfo);

    delete deltads;
    delete ds;
  } else if (mode_table) {
    if ((!table_row_names) | (!table_col_names)) {
      cerr << "ptlstats: Error: must specify both -rows and -cols options for the table mode", endl;
      return 1;
    }

    int tabletype = TABLE_TYPE_TEXT;
    if (strequal(table_type_name, "text"))
      tabletype = TABLE_TYPE_TEXT;
    else if (strequal(table_type_name, "latex"))
      tabletype = TABLE_TYPE_LATEX;
    else if (strequal(table_type_name, "html"))
      tabletype = TABLE_TYPE_HTML;
    else {
      cerr << "ptlstats: Error: unknown table type '", table_type_name, "'", endl;
      return 1;
    }

    create_table(cout, tabletype, mode_table, table_row_names, table_col_names, table_row_col_pattern, table_scale_rel_to_col);
  } else {
    idstream is(filename);
    if (!is) {
      cerr << "ptlstats: Cannot open '", filename, "'", endl, endl;
      return 2;
    }

    DataStoreNode* ds = new DataStoreNode(is);

    if (mode_subtree) {
      ds = ds->searchpath(mode_subtree);

      if (!ds) {
        cerr << "ptlstats: Error: cannot find subtree '", mode_subtree, "'", endl;
        return 1;
      }
    }

    ds->print(cout, printinfo);
    delete ds;
  }
}
