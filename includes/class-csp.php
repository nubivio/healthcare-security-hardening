<?php
/** CSP report-only inventory, endpoint, and SRI detector. @package Nubivio_HSH */
if (!defined('ABSPATH')) { exit; }
class Nubivio_HSH_Csp {
    private $core;
    public function __construct($core) { $this->core=$core; }
    public function run() {
        $o=$this->core->get_options(); $findings=array();$counts=array('high'=>0,'medium'=>0,'low'=>0);
        $sri=$this->audit_sri();
        if (!empty($sri['candidates'])) { $n=count($sri['candidates']);$findings[]=array('severity'=>'low','message'=>sprintf(_n('%d external script is a candidate for Subresource Integrity. Consider pinning it with `integrity` attributes.','%d external scripts are candidates for Subresource Integrity. Consider pinning them with `integrity` attributes.',$n,'nubivio-healthcare-security-hardening'),$n));$counts['low']++; }
        return array('findings'=>$findings,'counts'=>$counts,'summary'=>array('enabled'=>!empty($o['csp_enabled']),'inventory_at'=>isset($o['csp_inventory_at'])?(int)$o['csp_inventory_at']:0,'inline_scripts'=>isset($o['csp_inline_scripts'])?(int)$o['csp_inline_scripts']:0,'seen_hosts'=>isset($o['csp_seen_hosts'])?(array)$o['csp_seen_hosts']:array(),'violations'=>isset($o['csp_violations'])?(array)$o['csp_violations']:array(),'sri'=>$sri));
    }
    public function refresh_inventory() {
        delete_transient('nubivio_hsh_csp_html_' . md5((string) home_url('/')));
        return $this->run_inventory_scan();
    }
    public function run_inventory_scan() {
        $key='nubivio_hsh_csp_html_'.md5((string)home_url('/'));$html=get_transient($key);
        if (!is_string($html)) { $res=wp_remote_get(home_url('/'),array('timeout'=>10,'user-agent'=>'Nubivio-HSH/2.4 inventory')); if(is_wp_error($res)) return false; $html=(string)wp_remote_retrieve_body($res);set_transient($key,$html,DAY_IN_SECONDS); }
        $hosts=array('script-src'=>array(),'style-src'=>array(),'font-src'=>array(),'img-src'=>array(),'frame-src'=>array(),'connect-src'=>array());
        $site=$this->registered_site_host(); $inline_scripts = 0;
        if (class_exists('DOMDocument')) {
            $previous=libxml_use_internal_errors(true);$dom=new DOMDocument();$dom->loadHTML($html);libxml_clear_errors();libxml_use_internal_errors($previous);
            foreach ($dom->getElementsByTagName('script') as $node) {
                if ($node->getAttribute('src') === '') $inline_scripts++;
                else $this->add_host($hosts['script-src'], $node->getAttribute('src'));
            }
            foreach ($dom->getElementsByTagName('link') as $node) { $rel=strtolower($node->getAttribute('rel'));$href=$node->getAttribute('href'); if(strpos($rel,'stylesheet')!==false)$this->add_host($hosts['style-src'],$href);if(strpos($rel,'preload')!==false&&strtolower($node->getAttribute('as'))==='font')$this->add_host($hosts['font-src'],$href); }
            foreach ($dom->getElementsByTagName('img') as $node)$this->add_host($hosts['img-src'],$node->getAttribute('src'));
            foreach ($dom->getElementsByTagName('iframe') as $node)$this->add_host($hosts['frame-src'],$node->getAttribute('src'));
        }
        if (preg_match_all('/@font-face[^}]*url\(([^)]+)\)/i',$html,$m)) foreach($m[1] as $url)$this->add_host($hosts['font-src'],trim($url," \t\"'"));
        foreach($hosts as $directive=>$list) { $hosts[$directive]=array_values(array_filter(array_unique($list),function($h)use($site){return $h!==''&&$h!==$site;}));$hosts[$directive]=array_slice($hosts[$directive],0,50); }
        $o=$this->core->get_options();$o['csp_seen_hosts']=$hosts;$o['csp_inline_scripts']=$inline_scripts;$o['csp_inventory_at']=time();update_option(Nubivio_HSH::OPTION,$o);return true;
    }
    public function emit_report_only_header() {
        if(is_admin())return;$o=$this->core->get_options();if(empty($o['csp_enabled'])||empty($o['csp_inventory_at']))return;$seen=isset($o['csp_seen_hosts'])?(array)$o['csp_seen_hosts']:array();
        $part=function($directive)use($seen){$hosts=isset($seen[$directive])?(array)$seen[$directive]:array();$out=array();foreach($hosts as $host){$host=$this->header_host($host);if($host!=='')$out[]='https://'.$host;}return implode(' ',array_unique($out));};
        $policy="default-src 'self'; script-src 'self' ".$part('script-src')."; style-src 'self' 'unsafe-inline' ".$part('style-src')."; img-src 'self' data: https: ".$part('img-src')."; font-src 'self' data: ".$part('font-src')."; connect-src 'self' ".$part('connect-src')."; frame-src ".$part('frame-src')."; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; report-uri /wp-json/nubivio-hsh/v1/csp-report";
        header('Content-Security-Policy-Report-Only: '.preg_replace('/\s+/',' ',trim($policy)),true);
    }
    public function register_route() { register_rest_route('nubivio-hsh/v1','/csp-report',array('methods'=>'POST','callback'=>array($this,'handle_report'),'permission_callback'=>'__return_true')); }
    public function handle_report($request) {
        $ip=!empty($_SERVER['REMOTE_ADDR'])?sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])):'unknown';$key='nubivio_hsh_csp_rl_'.md5($ip);$rate=get_transient($key);$rate=is_array($rate)?$rate:array('count'=>0);$rate['count']++;set_transient($key,$rate,MINUTE_IN_SECONDS);if($rate['count']>100)return new WP_REST_Response(null,429);
        $body=method_exists($request,'get_body')?$request->get_body():'';$data=json_decode($body,true);if(isset($data['csp-report']))$data=$data['csp-report'];if(isset($data[0])&&is_array($data[0]))$data=isset($data[0]['body'])?$data[0]['body']:$data[0];if(!is_array($data))return new WP_REST_Response(null,204);
        $doc=isset($data['document-uri'])?(string)$data['document-uri']:'';$blocked=isset($data['blocked-uri'])?(string)$data['blocked-uri']:'';$directive=isset($data['effective-directive'])?(string)$data['effective-directive']:(isset($data['violated-directive'])?(string)$data['violated-directive']:'');
        if(preg_match('#^(chrome-extension|moz-extension|safari-web-extension)://#i',$blocked)||(in_array($blocked,array('data:','blob:'),true)&&$doc==='')||strtolower((string)wp_parse_url($doc,PHP_URL_HOST))!==$this->site_host())return new WP_REST_Response(null,204);
        $o=$this->core->get_options();$items=isset($o['csp_violations'])&&is_array($o['csp_violations'])?$o['csp_violations']:array();$now=time();$found=false;foreach($items as &$item){if(isset($item['directive'],$item['blocked_uri'])&&$item['directive']===$directive&&$item['blocked_uri']===$blocked){$item['last_seen']=$now;$item['count']=isset($item['count'])?(int)$item['count']+1:1;$found=true;break;}}unset($item);if(!$found)$items[]=array('directive'=>$directive,'blocked_uri'=>$blocked,'first_seen'=>$now,'last_seen'=>$now,'count'=>1,'sample_document_uri'=>$doc,'sample_ua'=>substr(isset($_SERVER['HTTP_USER_AGENT'])?(string)$_SERVER['HTTP_USER_AGENT']:'',0,200));usort($items,function($a,$b){return(int)$b['count']<=> (int)$a['count'];});$o['csp_violations']=array_slice($items,0,200);update_option(Nubivio_HSH::OPTION,$o);return new WP_REST_Response(null,204);
    }
    public function add_to_allowlist($directive,$blocked) { $host=$this->host_from_url($blocked);$allowed=array('script-src','style-src','font-src','img-src','frame-src','connect-src');if($host===''||!in_array($directive,$allowed,true))return false;$o=$this->core->get_options();if(!isset($o['csp_seen_hosts'])||!is_array($o['csp_seen_hosts']))$o['csp_seen_hosts']=array();if(!isset($o['csp_seen_hosts'][$directive])||!is_array($o['csp_seen_hosts'][$directive]))$o['csp_seen_hosts'][$directive]=array();if(!in_array($host,$o['csp_seen_hosts'][$directive],true))$o['csp_seen_hosts'][$directive][]= $host;$o['csp_seen_hosts'][$directive]=array_slice($o['csp_seen_hosts'][$directive],0,50);update_option(Nubivio_HSH::OPTION,$o);return true; }
    public function audit_sri() { $key='nubivio_hsh_csp_html_'.md5((string)home_url('/'));$html=get_transient($key);$out=array('dynamic'=>array(),'candidates'=>array());if(!is_string($html)||$html==='')return$out;$patterns=apply_filters('nubivio_hsh_sri_dynamic_hosts',array('googletagmanager.com','google-analytics.com','googleadservices.com','facebook.net','connect.facebook.net','hotjar.com','intercom.io','intercomcdn.com','hs-scripts.com','hs-analytics.net','hsforms.net','linkedin.com/analytics','bing.com','clarity.ms','mixpanel.com','segment.com','segment.io','fullstory.com','cloudflareinsights.com','usercentrics.com','cookiebot.com','iubenda.com'));$urls=array();if(preg_match_all('/<(?:script|link)\b[^>]+(?:src|href)=["\']([^"\']+)["\'][^>]*>/i',$html,$m))$urls=$m[1];foreach(array_unique($urls)as$url){$host=$this->host_from_url($url);if($host===''||$host===$this->registered_site_host())continue;$dynamic=false;foreach((array)$patterns as $p)if(strpos($host,(string)$p)!==false){$dynamic=true;break;}if($dynamic)$out['dynamic'][]=$url;else$out['candidates'][]=$url;}return$out; }
    private function add_host(&$list,$url){$host=$this->host_from_url($url);if($host!==''&&!in_array($host,$list,true)&&count($list)<50)$list[]=$host;} private function host_from_url($url){$url=trim((string)$url);if($url===''||preg_match('#^(data:|blob:|about:)#i',$url))return'';if(strpos($url,'//')===0)$url='https:'.$url;if(strpos($url,'://')===false)return'';$host=strtolower((string)wp_parse_url($url,PHP_URL_HOST));if($host==='')return'';$parts=explode('.',$host);return count($parts)>2?implode('.',array_slice($parts,-2)):$host;} private function header_host($host){return preg_replace('/[^a-z0-9.-]/i','',strtolower((string)$host));}
    private function site_host(){return strtolower((string)wp_parse_url(home_url(),PHP_URL_HOST));}
    private function registered_site_host(){return $this->registered_host($this->site_host());}
    private function registered_host($host){$parts=explode('.',strtolower((string)$host));return count($parts)>2?implode('.',array_slice($parts,-2)):(string)$host;}
}
